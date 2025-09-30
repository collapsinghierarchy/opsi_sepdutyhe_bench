cmake_minimum_required(VERSION 3.10)
project(OpenFHEPoC)

set(CMAKE_CXX_STANDARD 17)

# Let CMake find OpenFHE's config file
set(OpenFHE_DIR "/usr/local/lib/OpenFHE" CACHE PATH "Path to OpenFHE CMake config")

find_package(OpenFHE REQUIRED CONFIG)
find_package(OpenMP  REQUIRED)

#add_executable(main little_fermat.cpp)
#add_executable(main bit_compression.cpp)
add_executable(main eq_BGV_multi_sender_bench.cpp)


target_include_directories(main PRIVATE 
    /usr/local/include
    /usr/local/include/openfhe/core
    /usr/local/include/openfhe/cereal
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/binfhe

)

# Link the PKE library target
#target_link_libraries(main OPENFHEpke)
target_link_libraries(main
    PRIVATE
        OPENFHEpke           # imported from OpenFHE’s config
        OpenMP::OpenMP_CXX     # enables -fopenmp and links libgomp / libomp
)


# Equality indicator benchmark (BGV): frobenius vs fermat
add_executable(eq_indicator_bench eq_indicator_bench.cpp)

target_include_directories(eq_indicator_bench
    PRIVATE
        /usr/local/include
        /usr/local/include/openfhe/core
        /usr/local/include/openfhe/cereal
        /usr/local/include/openfhe/pke
        /usr/local/include/openfhe/binfhe
)

target_link_libraries(eq_indicator_bench
    PRIVATE
        OPENFHEpke
        OpenMP::OpenMP_CXX
)
