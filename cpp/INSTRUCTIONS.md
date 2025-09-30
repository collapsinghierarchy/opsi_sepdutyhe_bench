# opsi_sepdutyhe_bench (OpenFHE C++)

## Running Locally

> **Note:** Install [OpenFHE](https://github.com/openfheorg/openfhe-development) first.

```sh
git clone --depth 1 --branch v1.1.1 https://github.com/openfheorg/openfhe-development.git
cmake -S openfhe-development -B openfhe-build \
      -DCMAKE_BUILD_TYPE=Release \
      -DWITH_TESTS=OFF -DWITH_EXAMPLES=OFF -DWITH_BENCHMARKS=OFF \
      -DWITH_NTL=ON
cmake --build openfhe-build -j$(nproc)
cmake --install openfhe-build   # → /usr/local/{include,lib}
```
```sh
mkdir build
cp passengers.csv ./build/ 
cd build

cmake ..
make
./main
```
Then you should see
```sh
[INFO] columnsPerSender = 4
[INFO] nSenders         = 4096
[INFO] ringDim          = 16384
[INFO] totalValues      = 16384
[INFO] aggCount         = 1
[TIMER] context+keys          : 137 ms
[TIMER] ref encryption        : 32 ms
[TIMER] sender phase          : 0 ms
[TIMER] packing               : 24 ms
[TIMER] diff+mask             : 75 ms
[TIMER] bulk decrypt          : 8 ms
[TIMER] row count             : 0 ms
Encrypted COUNT(*)  = 41
Plaintext COUNT(*)  = 41
Correctness         = OK
```
## Docker
```sh
docker build -t he-bench .

docker run --rm \
  -v "$(pwd)/passengers.csv":/data/passengers.csv:ro \
  he-bench /data/passengers.csv
```
# The protocol
## Encrypted SQL `COUNT(*)` Benchmark – Pseudocode

### Symbols

| Symbol | Meaning |
|--------|---------|
| `m` | number of **rows** (senders) in the CSV |
| `c` | number of **columns** (`columnsPerSender`) |
| `N` | BGV ring dimension (`ringDim`) |
| `p` | plaintext modulus (fixed 65 537) |
| `Agg = ceil(m·c / N)` | number of ciphertext slices (“aggregates”) |

---

### Phase 0 · Pre-processing

```text
rows   ←  CSV(path)                      // vector<vector<string>>
hash16 ←  fast 16-bit hash function
rows16 ←  map each cell of rows through hash16      // uint16_t

query  ←  { colIdx : {allowedString₁,…,allowedString_k} }  // OR-sets
ref16  ←  wildcard vector of size c  (0xFFFF)
for each (col, values) in query:
        ref16[col] ←  hash16(values[1])   // singletons → degree-1 poly
        // if |values|>1 we need polynomial method (omitted here)

padding: while (rows16.size · c) % N ≠ 0
             append random dummy row to rows16
m ← rows16.size
```
### Phase 1 · Crypto context and keys
```text
cc  ←  GenCryptoContext( p = 65 537, N, depth = 2, 128-bit security )
(pk, sk) ←  KeyGen(cc)
EvalMultKeyGen(sk)
```