// eq_bgv_multi_sender_bench.cpp  (OpenFHE ≥ 1.2.x, C++17)
// -----------------------------------------------------------------------------
// Homomorphic encryption benchmarks for equality-matching and SQL-style queries
// using OpenFHE's BGV scheme. Includes CSV ingestion, reference row filtering,
// sender row packing, and correctness checks.
// -----------------------------------------------------------------------------

#include "openfhe/pke/openfhe.h"
#include <thread>
#include <random>
#include <vector>
#include <iostream>
#include <fstream>
#include <omp.h>
#include <unordered_set>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <sstream>
#include <unordered_map>

using namespace lbcrypto;

// --------------------------------------------------------------------------
// Count matching rows (skip columns where ref16[col] == 0xFFFF)
// --------------------------------------------------------------------------
std::size_t count_row_matches_once(
    const std::vector<Ciphertext<DCRTPoly>>& ctMasked,
    const CryptoContext<DCRTPoly>& cc,
    const PrivateKey<DCRTPoly>& sk,
    std::size_t columnsPerSender,
    std::size_t nSenders,
    std::size_t ringDim,
    const std::vector<uint16_t>& ref16,
    long& decrypt_ms,
    long& count_ms)
{
    using clock = std::chrono::high_resolution_clock;
    auto ms = [](auto d) { return std::chrono::duration_cast<std::chrono::milliseconds>(d).count(); };

    const std::size_t aggCount = ctMasked.size();

    // 1. bulk decrypt
    auto tDec0 = clock::now();
    std::vector<std::vector<int64_t>> aggPlain(aggCount);
    for (std::size_t a = 0; a < aggCount; ++a) {
        Plaintext pt;
        cc->Decrypt(sk, ctMasked[a], &pt);
        pt->SetLength(ringDim);
        aggPlain[a] = pt->GetPackedValue();
    }
    auto tDec1 = clock::now();
    decrypt_ms = ms(tDec1 - tDec0);

    // 2. row-level test with wild-card skip
    auto tCnt0 = clock::now();
    std::size_t encRowMatches = 0;

    for (std::size_t s = 0; s < nSenders; ++s) {
        std::size_t globalStart = s * columnsPerSender;
        bool rowOK = true;

        for (std::size_t c = 0; c < columnsPerSender; ++c) {
            if (ref16[c] == 0xFFFF) continue;

            std::size_t globalIdx = globalStart + c;
            std::size_t aggIdx = globalIdx / ringDim;
            std::size_t slotOff = globalIdx % ringDim;

            if (aggPlain[aggIdx][slotOff] != 0) {
                rowOK = false;
                break;
            }
        }
        if (rowOK) ++encRowMatches;
    }
    auto tCnt1 = clock::now();
    count_ms = ms(tCnt1 - tCnt0);

    return encRowMatches;
}

// Simple 16-bit string hash (fast, non-cryptographic)
static inline uint16_t hash16(const std::string& s) {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : s) h = (h ^ c) * 1099511628211ull;
    return static_cast<uint16_t>(h & 0xFFFFu);
}

// Tiny CSV reader: splits by , or ;, trims spaces
std::vector<std::vector<uint16_t>>
load_csv_hashed(const std::string& path, char delim = ',') {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open CSV: " + path);

    std::vector<std::vector<uint16_t>> rows;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::vector<uint16_t> row;
        std::string cell;
        std::stringstream ss(line);
        while (std::getline(ss, cell, delim)) {
            cell.erase(0, cell.find_first_not_of(" \t\r\n"));
            cell.erase(cell.find_last_not_of(" \t\r\n") + 1);
            row.push_back(hash16(cell));
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

// Build reference-row hash vector from {colIdx→value-string} map
std::vector<uint16_t>
make_ref_row(std::size_t nCols,
    const std::unordered_map<std::size_t, std::string>& filters) {
    std::vector<uint16_t> ref(nCols, 0xFFFF);
    for (auto& [idx, val] : filters) {
        if (idx >= nCols)
            throw std::runtime_error("filter index out of range");
        ref[idx] = hash16(val);
    }
    return ref;
}

// Replace “wildcard” (0xFFFF) slots with actual data for slot-wise diff
void broadcast_ref_to_slices(const std::vector<uint16_t>& ref,
    std::size_t aggCount,
    std::size_t ringDim,
    std::vector<int64_t>& out) {
    out.resize(aggCount * ringDim);
    for (std::size_t a = 0; a < aggCount; ++a)
        for (std::size_t j = 0; j < ringDim; ++j)
            out[a * ringDim + j] = ref[j % ref.size()];
}

// High-level wrapper: load CSV → build sender rows → call benchmark
std::size_t encrypted_sql_count_csv(const std::string& csvPath,
    const std::unordered_map<std::size_t, std::string>& filters,
    std::size_t ringDim = 16384,
    bool skipSenderEncrypt = false)
{
    /** 0.  Ingest CSV  ***************************************************/
    auto rows16 = load_csv_hashed(csvPath);
    if (rows16.empty()) throw std::runtime_error("CSV is empty");

    const std::size_t columnsPerSender = rows16[0].size();
    const std::size_t nSenders = rows16.size();
    const std::size_t totalValues = columnsPerSender * nSenders;
    std::cout << "[INFO] columnsPerSender = " << columnsPerSender << "\n"
        << "[INFO] nSenders         = " << nSenders << "\n"
        << "[INFO] ringDim          = " << ringDim << "\n"
        << "[INFO] totalValues      = " << totalValues << "\n"
        << "[INFO] aggCount         = " << (totalValues / ringDim) << "\n";

    if (totalValues % ringDim != 0)
        throw std::runtime_error("ringDim must divide rows*cols");

    /* 0xFFFF wildcard → “match any” */
    auto ref16 = make_ref_row(columnsPerSender, filters);

    /** 1.  Crypto context + keys (exact copy of earlier code) ************/
    using clock = std::chrono::high_resolution_clock;
    auto ms = [](auto d) { return std::chrono::duration_cast<std::chrono::milliseconds>(d).count(); };

    auto t0 = clock::now();
    CCParams<CryptoContextBGVRNS> prm;
    prm.SetPlaintextModulus(65537);
    prm.SetRingDim(ringDim);
    prm.SetMultiplicativeDepth(2);
    prm.SetSecurityLevel(HEStd_128_classic);

    auto cc = GenCryptoContext(prm);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    auto t1 = clock::now();
    std::cout << "[TIMER] context+keys          : " << ms(t1 - t0) << " ms\n";

    /** 2.  build & encrypt reference slices *****************************/
    const std::size_t aggCount = totalValues / ringDim;
    std::vector<int64_t> refBroadcast;
    broadcast_ref_to_slices(ref16, aggCount, ringDim, refBroadcast);

    std::vector<Ciphertext<DCRTPoly>> ctRef(aggCount);
    for (std::size_t a = 0; a < aggCount; ++a) {
        ctRef[a] = cc->Encrypt(
            kp.publicKey,
            cc->MakePackedPlaintext(std::vector<int64_t>(
                refBroadcast.begin() + a * ringDim,
                refBroadcast.begin() + (a + 1) * ringDim)));
    }
    auto t2 = clock::now();
    std::cout << "[TIMER] ref encryption        : " << ms(t2 - t1) << " ms\n";

    /* ---------------- 3. Sender → aggregate ---------------------------*/
    std::vector<std::vector<Ciphertext<DCRTPoly>>> senderCts(aggCount);
    std::vector<std::vector<int64_t>> aggPlainTmp(aggCount, std::vector<int64_t>(ringDim, 0));
    std::vector<uint8_t> plainMatch(nSenders, 0);

    auto t3a = clock::now();
    for (std::size_t s = 0; s < nSenders; ++s) {
        const auto& row16 = rows16[s];

        // Check if this sender row matches the reference (for plaintext oracle)
        bool matches = true;
        for (std::size_t c = 0; c < columnsPerSender; ++c)
            if (ref16[c] != 0xFFFF && row16[c] != ref16[c]) { matches = false; break; }
        plainMatch[s] = matches;

        std::size_t start = s * columnsPerSender;
        std::size_t a = start / ringDim;
        std::size_t off = start % ringDim;

        if (!skipSenderEncrypt) {
            std::vector<int64_t> packed(ringDim, 0);
            for (std::size_t c = 0; c < columnsPerSender; ++c)
                packed[off + c] = row16[c];

            senderCts[a].push_back(
                cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(std::move(packed))));
        }
        else {
            constexpr int64_t P = 65537;
            for (std::size_t c = 0; c < columnsPerSender; ++c) {
                auto& slot = aggPlainTmp[a][off + c];
                slot += row16[c];
                if (slot >= P) slot -= P;
            }
        }
    }
    auto t3b = clock::now();
    std::cout << "[TIMER] sender phase          : " << ms(t3b - t3a) << " ms\n";

    /* ---------------- 3B. Aggregate → ctAggr --------------------------*/
    std::vector<Ciphertext<DCRTPoly>> ctAggr(aggCount);

    if (!skipSenderEncrypt) {
        for (std::size_t a = 0; a < aggCount; ++a) {
            ctAggr[a] = senderCts[a][0];
            for (std::size_t k = 1; k < senderCts[a].size(); ++k)
                cc->EvalAddInPlace(ctAggr[a], senderCts[a][k]);
        }
    }
    else {
        for (std::size_t a = 0; a < aggCount; ++a)
            ctAggr[a] = cc->Encrypt(
                kp.publicKey,
                cc->MakePackedPlaintext(std::move(aggPlainTmp[a])));
    }
    auto t4 = clock::now();
    std::cout << "[TIMER] packing               : " << ms(t4 - t3b) << " ms\n";

    /** 5.  diff + (reused) mask ******************************************/
    std::mt19937_64 rng{ 42 };
    std::uniform_int_distribution<int64_t> rMask(1, 65535);
    std::vector<int64_t> maskVec(ringDim);
    for (auto& v : maskVec) v = rMask(rng);
    auto ctMask = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(maskVec));

    std::vector<Ciphertext<DCRTPoly>> ctMasked(aggCount);
    for (std::size_t a = 0; a < aggCount; ++a) {
        auto diff = cc->EvalSub(ctAggr[a], ctRef[a]);
        ctMasked[a] = cc->EvalMult(diff, ctMask);
    }
    auto t5 = clock::now();
    std::cout << "[TIMER] diff+mask             : " << ms(t5 - t4) << " ms\n";

    /** 6. decrypt + row count ********************************************/
    long decMs = 0, cntMs = 0;
    auto encMatches = count_row_matches_once(
        ctMasked, cc, kp.secretKey,
        columnsPerSender, nSenders, ringDim,
        ref16, decMs, cntMs);
    std::cout << "[TIMER] bulk decrypt          : " << decMs << " ms\n";
    std::cout << "[TIMER] row count             : " << cntMs << " ms\n";

    /** 7. plaintext oracle & check ***************************************/
    std::size_t plainMatches = std::accumulate(plainMatch.begin(), plainMatch.end(), 0ul);
    std::cout << "Encrypted COUNT(*)  = " << encMatches << "\n"
        << "Plaintext COUNT(*)  = " << plainMatches << "\n"
        << "Correctness         = "
        << ((encMatches == plainMatches) ? "OK" : "MISMATCH!") << "\n";

    return encMatches;
}


int main() {
    std::unordered_map<std::size_t, std::string> query = {
        {0, "2"},
        {1, "2"},
        {2, "1688140800"},
        {3, "7248031"}
    };

    encrypted_sql_count_csv("passengers.csv", query, 16384, true);
    encrypted_sql_count_csv("passengers.csv", query, 16384, false);

    return 0;
}
