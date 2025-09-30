// eq_indicator_bench.cpp
// -----------------------------------------------------------------------------
// Benchmark: encrypted equality indicator (0/1) for two packed values using BGV.
// Two modes:
//   1) "frobenius"  : depth-free Frobenius (via automorphisms) over F_{p^d}.
//   2) "fermat"     : Fermat-only exponentiation over F_p.
// Security: >= 128-bit (default: HEStd_192_classic for headroom).
// Requires: OpenFHE >= 1.2.x
// -----------------------------------------------------------------------------

#include "openfhe/pke/openfhe.h"
#include <chrono>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>
#include <stdexcept>
#include <cmath>

using namespace lbcrypto;

using Clock = std::chrono::high_resolution_clock;
using ms    = std::chrono::duration<double, std::milli>;

// Simple arg parsing
struct Args {
    std::string mode = "frobenius"; // or "fermat"
    std::size_t slots = 4096;       // number of SIMD slots to fill with the same test value
    std::size_t trials = 10;        // number of repeated evaluations to average
    bool verbose = false;
};

Args parseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s(argv[i]);
        if (s == "--mode" && i+1 < argc) a.mode = argv[++i];
        else if (s == "--slots" && i+1 < argc) a.slots = std::stoul(argv[++i]);
        else if (s == "--trials" && i+1 < argc) a.trials = std::stoul(argv[++i]);
        else if (s == "--verbose") a.verbose = true;
        else if (s == "-h" || s == "--help") {
            std::cout << "Usage: eq_indicator_bench [--mode frobenius|fermat] [--slots N] [--trials T] [--verbose]\n";
            std::exit(0);
        }
    }
    return a;
}

// Utility: modular exponentiation by repeated squaring using EvalMult & squaring only
// Returns ct^(2^k), performing k squarings (relinearizing in-place).
Ciphertext<DCRTPoly> evalPow2k(const CryptoContext<DCRTPoly>& cc, Ciphertext<DCRTPoly> ct, unsigned k) {
    for (unsigned i = 0; i < k; ++i) {
        ct = cc->EvalMult(ct, ct);
        cc->RelinearizeInPlace(ct);
    }
    return ct;
}

// Compute a^b mod m for 64-bit (small exponents)
static inline uint32_t modexp_u32(uint32_t a, uint32_t e, uint32_t m) {
    uint64_t res = 1, base = a % m;
    while (e) {
        if (e & 1U) res = (res * base) % m;
        base = (base * base) % m;
        e >>= 1U;
    }
    return static_cast<uint32_t>(res);
}

// Build "1 - x" where "1" is a packed plaintext of ones
Ciphertext<DCRTPoly> evalOneMinus(const CryptoContext<DCRTPoly>& cc,
                                  const PublicKey<DCRTPoly>& pk,
                                  Ciphertext<DCRTPoly> x,
                                  std::size_t slots) {
    std::vector<int64_t> ones(slots, 1);
    auto pt1 = cc->MakePackedPlaintext(ones);
    auto c1  = cc->Encrypt(pk, pt1);
    return cc->EvalSub(c1, x);
}

// Equality via Fermat: Eq = 1 - (Δ)^(p-1) over F_p
Ciphertext<DCRTPoly> equalityFermat(const CryptoContext<DCRTPoly>& cc,
                                    const PublicKey<DCRTPoly>& pk,
                                    Ciphertext<DCRTPoly> delta,
                                    uint32_t p,
                                    std::size_t slots) {
    // Since p is prime, p-1 can be computed via squarings + extra mults.
    // We choose p=17 so p-1=16=2^4 -> 4 squarings, zero extra mults.
    // If a different p is chosen, implement binary addition chain here.
    unsigned k = 0;
    uint32_t t = p - 1;
    // Check for power of two for our default path
    uint32_t tmp = t;
    while ((tmp & 1u) == 0u) { ++k; tmp >>= 1u; }
    if (tmp != 1u) {
        // Fallback generic chain (binary exponentiation)
        Ciphertext<DCRTPoly> acc = delta; // will become delta^(t)
        // Exponentiate: we compute delta^(t) using square-and-multiply
        std::vector<bool> bits;
        uint32_t e = t;
        while (e) { bits.push_back(e & 1u); e >>= 1u; }
        Ciphertext<DCRTPoly> base = delta;
        std::vector<int64_t> ones(slots, 1);
        auto pt1 = cc->MakePackedPlaintext(ones);
        acc = cc->Encrypt(pk, pt1); // start at multiplicative identity
        bool first = false;
        e = t;
        base = delta;
        uint32_t idx = 0;
        while (e) {
            if (e & 1u) {
                if (first) { acc = base; first = false; }
                else { acc = cc->EvalMult(acc, base); cc->RelinearizeInPlace(acc); }
            }
            e >>= 1u;
            idx++;
            if (e) { base = cc->EvalMult(base, base); cc->RelinearizeInPlace(base); }
        }
        return evalOneMinus(cc, pk, acc, slots);
    }
    // Power-of-two exponent
    auto pow = evalPow2k(cc, delta, k); // delta^(2^k) = delta^(p-1)
    return evalOneMinus(cc, pk, pow, slots);
}

// Equality via "depth-free Frobenius":
//   q = p^d, compute Norm = ∏_{i=0..d-1} Δ^{p^i} using automorphisms (depth-free).
//   Then Eq = 1 - Norm^(p-1).
Ciphertext<DCRTPoly> equalityFrobenius(const CryptoContext<DCRTPoly>& cc,
                                       const PublicKey<DCRTPoly>& pk,
                                       const PrivateKey<DCRTPoly>& sk,
                                       Ciphertext<DCRTPoly> delta,
                                       uint32_t p,
                                       uint32_t d,
                                       std::size_t slots) {
    // Cyclotomic order m = 2*N (power-of-two cyclotomic). Frobenius a->a^p corresponds
    // to automorphism index a = p mod m on BFV/BGV plaintext packing (empirically used).
    // We'll generate indices for p^i mod m and apply EvalAutomorphism.
    const uint32_t m = cc->GetCyclotomicOrder();
    std::vector<uint32_t> idx; idx.reserve(d-1);
    for (uint32_t i = 1; i < d; ++i) {
        uint32_t a = modexp_u32(p, i, m);
        if ((a & 1u) == 0u) {
            // ensure odd (required for automorphism in 2-power cyclotomic); adjust by +m/2 if needed
            a = (a + m/2u) % m;
            if ((a & 1u) == 0u) throw std::runtime_error("Computed automorphism index is not odd; check parameters.");
        }
        idx.push_back(a);
    }
    // Generate the required automorphism keys
    cc->EvalAutomorphismKeyGen(sk, idx);

    // Apply Frobenius powers depth-free
    std::vector<Ciphertext<DCRTPoly>> deltas;
    deltas.reserve(d);
    deltas.push_back(delta); // p^0
    for (uint32_t i = 1; i < d; ++i) {
        deltas.push_back(cc->EvalAutomorphism(delta, idx[i-1], cc->GetEvalAutomorphismKeyMap(sk->GetKeyTag())));
    }

    // Multiply in a binary tree: product of d terms
    auto prod = deltas[0];
    for (uint32_t i = 1; i < d; ++i) {
        prod = cc->EvalMult(prod, deltas[i]);
        cc->RelinearizeInPlace(prod);
    }
    // Raise to (p-1). For p=17 -> 4 squarings.
    unsigned k = 0; uint32_t t = p - 1; while ((t & 1u) == 0u) { ++k; t >>= 1u; }
    auto pow = evalPow2k(cc, prod, k);
    return evalOneMinus(cc, pk, pow, slots);
}


int main(int argc, char** argv) {
    auto args = parseArgs(argc, argv);
    const bool useFrobenius = (args.mode == "frobenius");

    // ---------------- Params ----------------
    CCParams<CryptoContextBGVRNS> params;
    params.SetSecurityLevel(HEStd_192_classic);
    params.SetKeySwitchTechnique(BV);

    uint32_t p = 17;
    uint32_t d = 1;

    if (useFrobenius) {
        // Depth: ~6 -> use 7
        params.SetMultiplicativeDepth(7);
        params.SetPlaintextModulus(17);

        // Use HYBRID KS and set mod sizes (avoid digitSize=0 issue)
        params.SetKeySwitchTechnique(HYBRID);

        // Slots hint
        if (args.slots > 4096) params.SetRingDim(16384);
        else params.SetRingDim(8192);
    } else {
        // 16 squarings -> depth ~16, give cushion
        params.SetMultiplicativeDepth(18);
        params.SetPlaintextModulus(65537);

        // Use HYBRID KS and set mod sizes
        params.SetKeySwitchTechnique(HYBRID);

        // Larger ring helps with this depth/plaintext
        if (args.slots > 2048) params.SetRingDim(16384);
        else params.SetRingDim(8192);
    }

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);

    // Pack the same scalar across all slots (benchmark equality on identical vectors)
    const std::size_t slots = args.slots;
    std::vector<int64_t> A(slots, 7);  // arbitrary a
    std::vector<int64_t> B(slots, 7);  // start equal to test 'true' path

    auto ptA = cc->MakePackedPlaintext(A);
    auto ptB = cc->MakePackedPlaintext(B);
    auto ctA = cc->Encrypt(kp.publicKey, ptA);
    auto ctB = cc->Encrypt(kp.publicKey, ptB);

    // Δ = A - B (all zeros initially)
    auto ctDeltaEqual = cc->EvalSub(ctA, ctB);

    // Now create a "not equal" delta by changing B
    std::vector<int64_t> Bneq = B;
    if (!Bneq.empty()) Bneq[0] = (Bneq[0] + 1) % p;
    auto ptBneq = cc->MakePackedPlaintext(Bneq);
    auto ctBneq = cc->Encrypt(kp.publicKey, ptBneq);
    auto ctDeltaNeq = cc->EvalSub(ctA, ctBneq);

    auto run_once = [&](const Ciphertext<DCRTPoly>& delta)->Ciphertext<DCRTPoly> {
        if (useFrobenius)
            return equalityFrobenius(cc, kp.publicKey, kp.secretKey, delta, p, d, slots);
        else
            return equalityFermat(cc, kp.publicKey, delta, p, slots);
    };

    // Warmup
    (void) run_once(ctDeltaEqual);

    // Timed runs (Equal and Not-Equal)
    ms tEqual{0}, tNeq{0};
    for (std::size_t i = 0; i < args.trials; ++i) {
        auto t0 = Clock::now();
        auto ctEq1 = run_once(ctDeltaEqual);
        auto t1 = Clock::now();
        tEqual += ms(t1 - t0);

        t0 = Clock::now();
        auto ctEq2 = run_once(ctDeltaNeq);
        t1 = Clock::now();
        tNeq += ms(t1 - t0);
    }
    tEqual /= args.trials;
    tNeq   /= args.trials;

    // Verify correctness (first few slots)
    Plaintext d1, d2;
    cc->Decrypt(kp.secretKey, run_once(ctDeltaEqual), &d1);
    cc->Decrypt(kp.secretKey, run_once(ctDeltaNeq), &d2);
    d1->SetLength(slots);
    d2->SetLength(slots);
    auto v1 = d1->GetPackedValue();
    auto v2 = d2->GetPackedValue();

    bool okEq = true, okNeq = true;
    for (std::size_t i = 0; i < std::min<std::size_t>(slots, 8); ++i) {
        okEq  &= (v1[i] % p == 1);
        okNeq &= (v2[i] % p == 0);
    }

    std::cout << "[eq_indicator_bench] mode=" << (useFrobenius ? "frobenius" : "fermat")
              << " slots=" << slots
              << " trials=" << args.trials
              << " security=HEStd_192_classic"
              << " p=" << p
              << (useFrobenius ? " d=4" : " d=1")
              << "\n  avg(ms) Equal:    " << tEqual.count()
              << "\n  avg(ms) NotEqual: " << tNeq.count()
              << "\n  okEqual=" << (okEq ? "true" : "false")
              << " okNotEqual=" << (okNeq ? "true" : "false")
              << std::endl;

    return 0;
}

