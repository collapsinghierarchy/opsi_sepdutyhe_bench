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
	loop_num_input_clients := 17  // Number of Input Clients Loop (log2). Tested for X < 17
	const average_count int = 100 // Number retries for averaging

	output_timings := make([][]time.Duration, loop_num_input_clients-16) // Stores the measured timings: Calculator (w/Aggr.), Calculator (w/oAggr.) a, Decryptor, postprocessing (Initator)
	defer store_Timing(output_timings, "numclients_"+strconv.Itoa(loop_num_input_clients)+"_inputsize_"+strconv.Itoa(2)+"_logN_"+strconv.Itoa(13)+"_avg_"+strconv.Itoa(average_count), logger)
	//Loop over different number of input clients
	for i := 16; i < loop_num_input_clients; i++ {
		logger.Info("Starting loop "+strconv.FormatInt(int64(i+1), 10)+" / "+strconv.FormatInt(int64(loop_num_input_clients), 10), "Number of Clients", powInt(2, i))
		output_timings[i-16] = make([]time.Duration, 4) // init timings array
		for avg_count := range average_count {
			logger.Info("Start Initialization nr " + strconv.Itoa(avg_count))
			//-----------------Configuration of the Individual Run -----------------//
			num_input_clients := powInt(2, i)                                // Default number of input clients
			input_size := 2                                                  // Default number of input slots
			matching_target := int(RandUint24() % uint32(num_input_clients)) // Target that is matched, has to be < num_input_clients

			/*
			 * Creating encryption parameters (For more details see https://homomorphicencryption.org/standard/)
			 * logN = 13, logQP = 58, plaintext modulus T = 113246209 and a ternary distribution.
			 *
			 *
			 * Requirements for parameter tuning:
			 * - l*N must be greater than input_size*num_input_clients, i.e., number of overall slots, where l is the number of required ciphertexts, see the num_aggr_cts variable to fit all inputs.
			 * - N must be divisible by input_size (i.e., |input_size| = 2^k, where logN >> k) -> N/k is the maximum for num_input_clients
			 * - num_input_clients has to be exactly l*N/k. Otherwise this benchmark will not work correctly.
			 * - PlaintextModulus must be large enough to accommodate the size of individual inputs. Otherwise you will have to adapt an additional CRT representation.
			 */
			params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
				LogN:             13,
				LogQ:             []int{58},
				PlaintextModulus: 113246209, // 26 bits
				//PlaintextModulus: 65537,   // 16 bits
			})
			if err != nil {
				logger.Error(err.Error(), "Where?", "Parameter Init failed")
				panic(err)
			}

			if num_input_clients*input_size > params.MaxSlots() && (num_input_clients*input_size)%params.MaxSlots() != 0 {
				panic("In general clients at the end of a ciphertext might have some slots in the next cipher requiring two ciphertexts, but we assume here for simplicity that this never happens. This never happens, if num_input_clients*input_size % N == 0")
			}

			num_aggr_cts := int(math.Ceil(float64(input_size*num_input_clients) / float64(params.MaxSlots())))

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

			inputs := make([][]uint64, num_input_clients)
			matching_values := make([]uint64, input_size)
			//---Fill Input Arrays ---//
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
			//---Encrypt the Inputs---//
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
			inputs_mask := make([]uint64, params.MaxSlots()*num_aggr_cts)
			/*
			 * SIMD Encoding
			 *
			 * Initializer:
			 * --> (x_init_1, ..., x_init_n, x_init_1, ..., x_init_n, ..., x_init_1, ..., x_init_n)
			 * (The same set of n initial values is repeated m times across the plaintext slots of a single ciphertext)
			 *
			 * Input for Client i:
			 * --> (0, ..., 0, x_client_i*n, ..., x_client_((i+1)*n-1), 0, ..., 0)
			 * (The client's input is encoded into plaintext slots from index i*n to (i+1)*n-1, with 1s filling the rest)
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

			//---Encrypt the Input---//
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

			//---Encrypt the Mask---//
			cts_mask := make([]*rlwe.Ciphertext, num_aggr_cts)
			for k := range num_aggr_cts {
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
			start := time.Now()
			//---Init the Aggregation Ciphertexts---//
			ct_aggr := make([]*rlwe.Ciphertext, num_aggr_cts)
			for k := range num_aggr_cts {
				ct_aggr[k] = bgv.NewCiphertext(params, 1, params.MaxLevel())
			}

			//---Aggregate the Ciphertexts---//
			for k := range num_input_clients {
				ct_index := int(math.Ceil(float64((k * input_size) / params.MaxSlots()))) //Find out the ciphertext index of this client
				evaluator.Add(ct_aggr[ct_index], ct_inputs[k], ct_aggr[ct_index])         //Aggregate
			}
			runtime_aggregation := time.Since(start)

			//-------------------	Calculation Phase	-------------------
			for k := range num_aggr_cts {
				evaluator.Sub(ct_aggr[k], ct_init, ct_aggr[k]) // Compute the Matching
				ct_rnd := rlwe.NewCiphertextRandom(rand.Reader, params, 1, params.MaxLevel())
				evaluator.Mul(ct_aggr[k], ct_rnd, ct_aggr[k])      // Randomize the Matching
				evaluator.Add(ct_aggr[k], cts_mask[k], ct_aggr[k]) // Mask the Matching
			}
			runtime_calculator := time.Since(start)

			//-------------------	Decryption Phase	-------------------
			start = time.Now()
			res := make([][]uint64, num_aggr_cts)
			pt_dec := make([]*rlwe.Plaintext, num_aggr_cts)
			//---Decrypt the Result---//
			for k := range num_aggr_cts {
				res[k] = make([]uint64, params.MaxSlots())
				pt_dec[k] = bgv.NewPlaintext(params, params.MaxLevel())
				dec.Decrypt(ct_aggr[k], pt_dec[k])
				ecd_dec.Decode(pt_dec[k], res[k])
			}
			runtime_decryptor := time.Since(start)

			//-------------------	Post-Processing Phase	-------------------
			start = time.Now()
			psi_results := make([][]int, num_aggr_cts)
			for k := range num_aggr_cts {
				res[k] = Unmask(res[k], inputs_mask[k*params.MaxSlots():(k+1)*params.MaxSlots()])
				if params.MaxSlots()/input_size < num_input_clients {
					psi_results[k] = ScanForValue(res[k], uint64(params.MaxSlots()/input_size)-1)
				} else {
					psi_results[k] = ScanForValue(res[k], uint64(num_input_clients)-1)
				}
			}

			runtime_postprocessing := time.Since(start)
			logger.Info("Sanity Check", "Matching input client", matching_target)
			logger.Info("The following Input Clients have matching inputs with Initializer", "Indices", psi_results)
			//logger.Info("Benchmark Configuration", "Number of Clients", num_input_clients, "Input Size", input_size)
			logger.Info("Benchmark Timings", "Runtime Calculator with Aggregation", runtime_calculator, "Runtime Calculator without Aggregation", runtime_calculator-runtime_aggregation, "Runtime Decryptor", runtime_decryptor, "Runtime Postprocessing", runtime_postprocessing)

			output_timings[i-16][0] += runtime_calculator
			output_timings[i-16][1] += runtime_calculator - runtime_aggregation
			output_timings[i-16][2] += runtime_decryptor
			output_timings[i-16][3] += runtime_postprocessing
		}
		// calculate averages
		for ind := range output_timings[i-16] {
			output_timings[i-16][ind] = time.Duration(float64(output_timings[i-16][ind]) / float64(average_count))
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
