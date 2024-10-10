/*
* Authors: Wasilij Beskorovajnov (beskorovajnov@fzi.de) and Robert Brede
 */
package main

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Name of the folder in which the files are created
// /benchmarks/test_name

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	//----------------- Params for Benchmarking -----------------//
	// Number of Input Clients Loop (log2)
	// Tested for X < 17
	loop_num_input_clients := 15
	// how often to repeat each data point and average over
	const average_count int = 100
	logN := 13
	// stores the measured timings, first dimension j, second i, third the different timings: calculate, aggregate, decrypt, postprocess
	output_timings := make([][]time.Duration, loop_num_input_clients-10)
	defer store_Timing(output_timings, "numclients_"+strconv.Itoa(loop_num_input_clients)+"_inputsize_"+strconv.Itoa(2)+"_logN_"+strconv.Itoa(logN)+"_avg_"+strconv.Itoa(average_count), logger)
	//Loop over different number of input clients
	for i := 10; i < loop_num_input_clients; i++ {
		logger.Info("Starting loop "+strconv.FormatInt(int64(i+1), 10)+" / "+strconv.FormatInt(int64(loop_num_input_clients), 10), "Number of Clients", powInt(2, i))
		// init timings array
		output_timings[i-10] = make([]time.Duration, 4)
		for avg_count := range average_count {
			logger.Info("Start Initialization nr " + strconv.FormatInt(int64(avg_count), 10))
			//	Configuration of the Application
			num_input_clients := powInt(2, i)                                // Default number of input clients
			input_size := 2                                                  // Default number of input slots
			matching_target := int(RandUint24() % uint32(num_input_clients)) // Target that is matched, has to be < num_input_clients
			//matching_target := 1
			//matching_target_2 := 3
			//input_bitlength := 16                                            // Default length of each input in bit.

			/*
				TODO: update this comment
				 * Creating encryption parameters from default settings:
				 * logN = 14, logQP = 438, and plaintext modulus T = 65537.
				 *
				 * TODO: Optimize based on (num_input_clients, input_size)
				 *
				 * Assumptions:
				 * - N is greater than input_size*num_input_clients.
				 * - N is ideally divisible by input_size (i.e., |input_size| = 2^k, where logN >> k) -> N/k is the maximum for num_input_clients
				 *   (If this condition is not met, another aggregate ciphertext will need to be allocated.)
				 *
				 * Consideration:
				 * - logP must be large enough to accommodate the size of individual inputs. Otherwise we will have to adapt an additional CRT representation.
			*/
			params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
				LogN:             logN,
				LogQ:             []int{58},
				PlaintextModulus: 113246209, // max bitlength of a component is 26
				//PlaintextModulus: 65537, // max bitlength of a component is 16
			})
			if err != nil {
				logger.Error(err.Error(), "Where?", "Parameter Init failed")
				panic(err)
			}

			if num_input_clients*input_size > params.MaxSlots() && (num_input_clients*input_size)%params.MaxSlots() != 0 {
				panic("In general clients at the end of a ciphertext might have some slots in the next cipher requiring two ciphertexts, but we assume here for simplicity that this never happens. This never happens, if num_input_clients*input_size % N == 0")
			}

			nr_ciphers := int(math.Ceil(float64(input_size*num_input_clients) / float64(params.MaxSlots())))

			//-----------------	Init Decryptor -----------------//
			kgen := rlwe.NewKeyGenerator(params)
			sk, pk := kgen.GenKeyPairNew()
			dec := bgv.NewDecryptor(params, sk)
			ecd_dec := bgv.NewEncoder(params)

			//-----------------	Init Calculator -----------------//
			evaluator := bgv.NewEvaluator(params, nil)

			//-----------------	Init Input Clients -----------------//
			ecd_input := bgv.NewEncoder(params)
			enc_input := bgv.NewEncryptor(params, pk)
			// In general clients at the end of a ciphertext might have some slots in the next cipher requiring two ciphertexts, but we assume here for simplicity that this never happens.
			// This never happens, if num_input_clients*input_size % N == 0
			inputs := make([][]uint64, num_input_clients)
			matching_values := make([]uint64, input_size)
			for k := range num_input_clients {
				inputs[k] = make([]uint64, params.MaxSlots())
				for j := range params.MaxSlots() {
					inputs[k][j] = 1
				}
				for j := range input_size {
					ind := (k*input_size + j) % params.MaxSlots()
					inputs[k][ind] = uint64(RandUint24())
					if k == matching_target {
						matching_values[j] = inputs[k][ind]
					}
				}
			}

			pt_inputs := make([]*rlwe.Plaintext, num_input_clients)
			ct_inputs := make([]*rlwe.Ciphertext, num_input_clients)
			for k := range num_input_clients {
				pt_inputs[k] = bgv.NewPlaintext(params, params.MaxLevel())
				if err = ecd_input.Encode(inputs[k], pt_inputs[k]); err != nil {
					logger.Error(err.Error(), "Where?", "Error during Input Client Plaintext Encoding", "Pt", k)
					panic(err)
				}
				ct_inputs[k] = bgv.NewCiphertext(params, 1, params.MaxLevel())
				if err = enc_input.Encrypt(pt_inputs[k], ct_inputs[k]); err != nil {
					logger.Error(err.Error(), "Where?", "Error during Input Client Encryption", "Ct", k)
					panic(err)
				}
			}
			//-----------------	Init Initiating Party -----------------//
			ecd_init := bgv.NewEncoder(params)
			enc_init := bgv.NewEncryptor(params, pk)
			inputs_init := make([]uint64, params.MaxSlots())
			inputs_mask := make([]uint64, params.MaxSlots()*nr_ciphers)
			/*
			 * SIMD Encoding
			 *
			 * Initializer:
			 * --> (x_init_1, ..., x_init_n, x_init_1, ..., x_init_n, ..., x_init_1, ..., x_init_n)
			 * (The same set of n initial values is repeated m times across the plaintext slots.)
			 *
			 * Input for Client i:
			 * --> (0, ..., 0, x_client_i*n, ..., x_client_((i+1)*n-1), 0, ..., 0)
			 * (The client's input is encoded into plaintext slots from index i*n to (i+1)*n-1, with zeros filling the rest.)
			 *
			 * Where 'n' represents the size of the input, and 'm' represents the number of clients.
			 */

			for k := range num_input_clients {
				for j := range input_size {
					if k*input_size+j < params.MaxSlots() {
						inputs_init[k*input_size+j] = matching_values[j]
					}
					inputs_mask[k*input_size+j] = uint64(RandUint24())
				}
			}

			pt_init := bgv.NewPlaintext(params, params.MaxLevel())
			if err = ecd_init.Encode(inputs_init, pt_init); err != nil {
				logger.Error(err.Error(), "Where?", "Error during Initializer Input Encoding")
				panic(err)
			}
			ct_init := bgv.NewCiphertext(params, 1, params.MaxLevel())
			if err = enc_init.Encrypt(pt_init, ct_init); err != nil {
				logger.Error(err.Error(), "Where?", "Error during Initializer Input Encryption")
				panic(err)
			}
			cts_mask := make([]*rlwe.Ciphertext, nr_ciphers)

			for k := range nr_ciphers {
				pt_mask := bgv.NewPlaintext(params, params.MaxLevel())
				if err = ecd_init.Encode(inputs_mask[k*params.MaxSlots():(k+1)*params.MaxSlots()], pt_mask); err != nil {
					logger.Error(err.Error(), "Where?", "Error during Initializer Mask Encoding")
					panic(err)
				}
				ct_mask := bgv.NewCiphertext(params, 1, params.MaxLevel())
				if err = enc_init.Encrypt(pt_mask, ct_mask); err != nil {
					logger.Error(err.Error(), "Where?", "Error during Initializer Mask Encryption")
					panic(err)
				}
				cts_mask[k] = ct_mask
			}
			logger.Info("Initialization Finished")
			//-------------------	Outsourcing Phase	-------------------
			/*
			*	The Simulation of Network Communcation is skipped in this benchmark
			*
			 */
			// init ciphertexts
			ct_aggr := make([]*rlwe.Ciphertext, nr_ciphers)
			for k := range nr_ciphers {
				ct_aggr[k] = bgv.NewCiphertext(params, 1, params.MaxLevel())
			}
			start := time.Now()

			// aggregate all clients
			for k := range num_input_clients {
				//Find out the ciphertext index of this client
				ct_index := int(math.Ceil(float64((k * input_size) / params.MaxSlots())))
				evaluator.Add(ct_aggr[ct_index], ct_inputs[k], ct_aggr[ct_index])
			}
			runtime_aggregation := time.Since(start)

			//-------------------	Calculation Phase	-------------------
			for k := range nr_ciphers {
				evaluator.Sub(ct_aggr[k], ct_init, ct_aggr[k])
				ct_rnd := rlwe.NewCiphertextRandom(rand.Reader, params, 1, params.MaxLevel())
				evaluator.Mul(ct_aggr[k], ct_rnd, ct_aggr[k])
				evaluator.Add(ct_aggr[k], cts_mask[k], ct_aggr[k]) // Apply encrypted mask
			}
			runtime_calculator := time.Since(start)

			//-------------------	Decryption Phase	-------------------
			start = time.Now()
			// first dimension is the number of cipher, the second the plaintext values
			res := make([][]uint64, nr_ciphers)
			pt_dec := make([]*rlwe.Plaintext, nr_ciphers)
			// decrypt all ciphers
			for k := range nr_ciphers {
				res[k] = make([]uint64, params.MaxSlots())
				pt_dec[k] = bgv.NewPlaintext(params, params.MaxLevel())
				dec.Decrypt(ct_aggr[k], pt_dec[k])
				ecd_dec.Decode(pt_dec[k], res[k])
			}
			runtime_decryptor := time.Since(start)

			//-------------------	Post-Processing Phase	-------------------
			start = time.Now()
			psi_results := make([][]int, nr_ciphers)
			//matching_failed := false
			for k := range nr_ciphers {
				res[k] = Unmask(res[k], inputs_mask[k*params.MaxSlots():(k+1)*params.MaxSlots()])
				if params.MaxSlots()/input_size < num_input_clients {
					psi_results[k] = ScanForValue(res[k], uint64(params.MaxSlots()/input_size)-1)
				} else {
					psi_results[k] = ScanForValue(res[k], uint64(num_input_clients)-1)
				}
			}
			/*
				if matching_failed {
					logger.Info("Sanity Check", "Matching failed with matching target", matching_target)
					panic("Should have matched with at least one client!")
				}
			*/
			runtime_postprocessing := time.Since(start)
			logger.Info("Sanity Check", "Matching input client", matching_target)
			logger.Info("The following Input Clients have matching inputs with Initializer", "Indices", psi_results)
			//logger.Info("Benchmark Configuration", "Number of Clients", num_input_clients, "Input Size", input_size)
			logger.Info("Benchmark Timings", "Runtime Calculator with Aggregation", runtime_calculator, "Runtime Calculator without Aggregation", runtime_calculator-runtime_aggregation, "Runtime Decryptor", runtime_decryptor, "Runtime Postprocessing", runtime_postprocessing)
			// store timings

			output_timings[i-10][0] += runtime_calculator
			output_timings[i-10][1] += runtime_calculator - runtime_aggregation
			output_timings[i-10][2] += runtime_decryptor
			output_timings[i-10][3] += runtime_postprocessing
		}
		// calculate averages
		for ind := range output_timings[i-10] {
			output_timings[i-10][ind] = time.Duration(float64(output_timings[i-10][ind]) / float64(average_count))
		}
	}
}

func powInt(x, y int) int {
	return int(math.Pow(float64(x), float64(y)))
}

func Unmask(masked_res []uint64, mask []uint64) (res []uint64) {
	for i := range masked_res {
		masked_res[i] = masked_res[i] - mask[i]
	}
	return masked_res
}

func ScanForValue(values []uint64, value uint64) (value_indices []int) {
	for i := range values {
		if values[i] == value {
			value_indices = append(value_indices, i)
		}
	}
	return value_indices
}

/*
* TODO: If RandUint16/64/BigInt() is used for purposes other than security (e.g., random data for testing or benchmarking),
* consider switching to math/rand instead of crypto/rand for better performance.
 */
func RandUint64() uint64 {
	b := []byte{0, 0, 0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b)
}

func RandUint24() uint32 {
	b := []byte{0, 0, 0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint32(b) % 16777216
}

func RandUint16() uint16 {
	b := []byte{0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(b)
}

// creates a file for each iteration of the outer loop
// stores the timings in the format
// calc_1 aggr_1 decr_1 post_1
// calc_2 aggr_2 decr_2 post_2
// ...
func store_Timing(timings [][]time.Duration, bench_name string, logger *slog.Logger) {
	logger.Info("Saving Benchmarks", "bench_name", bench_name)
	f, err := os.Create("benchmarks/runtimes__" + bench_name)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, list := range timings {
		output := ""
		for _, timings := range list {
			output = output + " " + timings.String()
		}
		f.WriteString(output + "\n")
	}
}
