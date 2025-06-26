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