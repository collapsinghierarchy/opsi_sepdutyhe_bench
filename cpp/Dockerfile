FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential cmake git \
        libgmp-dev libntl-dev libboost-all-dev \
        libcereal-dev  \                  
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

# -- OpenFHE (Release) -------------------------------------------------------
WORKDIR /opt
RUN git clone --depth 1 --branch v1.1.1 https://github.com/openfheorg/openfhe-development.git && \
    cmake -S openfhe-development -B openfhe-build \
          -DCMAKE_BUILD_TYPE=Release \
          -DWITH_TESTS=OFF -DWITH_EXAMPLES=OFF -DWITH_BENCHMARKS=OFF \
          -DWITH_NTL=ON && \
    cmake --build openfhe-build -j$(nproc) && \
    cmake --install openfhe-build   # → /usr/local/{include,lib}

# -- your benchmark sources (ONLY the two required files) --------------------
WORKDIR /proj
COPY CMakeLists.txt .
COPY eq_BGV_multi_sender_bench.cpp .
 

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(nproc)

##################### 2 ──── runtime stage  ##################################
FROM ubuntu:22.04

# runtime libs only
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        libgmp10 libntl44 libgomp1 && \
    rm -rf /var/lib/apt/lists/*

# copy OpenFHE libs
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/lib/OpenFHE /usr/local/lib/OpenFHE
ENV LD_LIBRARY_PATH=/usr/local/lib

# copy benchmark binary (built as 'main' in your CMakeLists.txt)
COPY --from=builder /proj/build/main /usr/local/bin/he-benchmark

WORKDIR /data
ENTRYPOINT ["/usr/local/bin/he-benchmark"]
