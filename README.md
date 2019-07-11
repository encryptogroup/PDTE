# Private Decision Tree Evaluation (PDTE) Protocols

By *Ágnes Kiss* ([ENCRYPTO](http://www.encrypto.de), TU Darmstadt), *Masoud Naderpour* (University of Helsinki), *Jian Liu* (University of California, Berkeley), *N. Asokan* (Aalto University) and *Thomas Schneider* ([ENCRYPTO](http://www.encrypto.de), TU Darmstadt) in [PoPETs'19(2)](https://petsymposium.org/2019/). Paper available [here](http://encrypto.de/papers/KNLAS19.pdf)

### Features
---

Our implementation for private decision tree evaluation protocols includes the protocols HHH, HGH, GGH, GGG and HGG (it can also be used to benchmark the last and most inefficient protocol HHG). The implementation of (SelH+)CompH and PathH is based on the mcl library (https://github.com/herumi/mcl) that implements efficient lifted ElGamal encryption over elliptic curves, more specifically on the XCMP protocol implementation which implements the DGK comparison protocol (https://github.com/fionser/XCMP). The implementation of SelH, SelG, CompG and PathG are based on the ABY framework (https://github.com/encryptogroup/ABY) which provides an efficient implementation of Yao's garbled circuit protocol as well as of the Paillier homomorphic encryption scheme.

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

### Requirements
---
The requirements are the same as that of https://github.com/fionser/XCMP and https://github.com/encryptogroup/ABY.

### PDTE Implementation
---

1. Clone a copy of the main PDTE git repository by running:
```
git clone --recursive git://github.com/encryptogroup/PDTE
```
2. Enter the UC directory: `cd PDTE`

#### (SelH+)CompH and PathH Implementation
3. Clone/download the XCMP repository in the PDTE folder
4. Place/replace the files from XCMP_files into the respective location in the XCMP folder
5. Add the following lines at the enf of XCMP/benchmark_gt/CMakeLists.txt:
```
add_executable(hhh hhh.cpp)
target_link_libraries(hhh boost_system pthread ${ECC_LIB})
```
6. Run the following commands:
```
cd benchmark_gt
mkdir build & cd build
cmake .. -DCMAKE_BUILD_TYPE=Release & make
```
7. In two separate terminals, run ```./hhh 0``` and ```./hhh 1``` for the server and client applications. You can configure the DT and PROT variables in the beginning of the file benchmark_dt/hhh.cpp for running different protocol parts and decision trees. 
