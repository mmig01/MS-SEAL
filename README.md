# Contents
- [`Abstract`](#1-abstract)
- [`Implementation`](#2-implementation)
- [`Test`](#3-test)
- [`Example Code`](#4-example-code)
- [`References`](#5-references)

</br>

# 1. Abstract

This project provides an implementation of CKKS bootstrapping based on Microsoft SEAL.
Both sparse and non-sparse secret key variants are supported.

The bootstrapping process consists of the following core steps:
- Modulus raising (q_l -> Q)
- Coefficient-to-Slot using BSGS (CTS) 
- Approximate modulus reduction using Taylor series (Eval Mod q_l) 
- Slot-to-Coefficient using BSGS (STC) 

This code is designed for testing and analyzing the CKKS bootstrapping pipeline with configurable parameters and performance measurements.

**For any inquiries or feedback, please use the GitHub Issues tab or contact us at:**
> **Email: [`java_script@kakao.com`](java_script@kakao.com)**

</br>

# 2. Implementation

### 1) CKKSBootstrapper (class)
- Provides CKKS bootstrapping operations to refresh and reduce noise in CKKS ciphertexts.
- Implements core functions for bootstrapping, including modulus extension, CTS, STC, approximate modulus reduction, and correction factor, among others.
- Source files:
  - [`CKKSBootstrapper.h`](/native/src/seal/bootstrapper.h)
  - [`CKKSBootstrapper.cpp`](/native/src/seal/bootstrapper.cpp)

### 2) fastbconv_Q (function)
- Fast base conversion from q_l to Q.
- Source files:
  - [`rns.h`](/native/src/seal/util/rns.h#L211-L215)
  - [`rns.cpp`](/native/src/seal/util/rns.cpp#L912-L935)
    
### 3) mod_raise_to_first, mod_raise_to_first_inplace (function)
- Raises the modulus of a ciphertext to the highest (initial) modulus level in the modulus switching chain.
- Source files:
  - [`evaluator.h`](/native/src/seal/evaluator.h#L490-L534)
  - [`evaluator.cpp`](/native/src/seal/evaluator.cpp#L1603-L1658)

### 4) is_valid_bootstrapping_depth, set_bootstrapping_depth (function)
- Validate or set the bootstrapping depth based on circuit parameters.
- Source files:
  - [`encryptionparams.h`](/native/src/seal/encryptionparams.h)
  - [`encryptionparams.cpp`](/native/src/seal/encryptionparams.cpp)

### 5) Context (class)
- Defines entry_context and entry_parms_id.
- Checks whether the encryption parameters are secure under the HomomorphicEncryption.org security standard, taking bootstrapping depth into account.
- Creates an RNSTool instance required for bootstrapping.
- Source files:
  - [`context.h`](/native/src/seal/context.h)
  - [`context.cpp`](/native/src/seal/context.cpp)
    
</br>

# 3. Test

### 1) Test Environment
- CPU: Intel Core i5-8500 @ 3.00GHz
- RAM: 32 GB
- OS: Windows 11 Pro (Version 24H2, Build 26100.4349)
- Architecture: 64-bit, x64-based processor
- Compiler: Microsoft Visual Studio (MSVC), C++17
- Build Configuration: Release

---

### 2) Test Summary

| Test ID   | Secret Key | log(q_0) | log(Q) | log(scale) | log(delta) | Bootstrapping Depth | Avg Precision (bits) | Time (s) |
|-----------|------------|--------|--------|--------|--------|----------------------|--------------------|----------|
| Test 1    | Sparse     | 60   | 1602   | 51   | 60   | 23                   | ≈2<sup>-14.9</sup> | 55.252   |
| Test 2    | Sparse     | 60   | 3522   | 51   | 120   | 55                   | ≈2<sup>-17.4</sup> | 173.744  |
| Test 3    | Non-sparse | 60   | 1602   | 51   | 60   | 23                   | ≈2<sup>-12.5</sup> | 55.240   |
| Test 4    | Non-sparse | 60   | 3522   | 51   | 120   | 55                   | ≈2<sup>-12.6</sup> | 175.830  |

---

### 3) Test Details

### Test 1

**Average Precision:** ≈ 2<sup>-14.9</sup>  
**Total Execution Time:** `55.252 seconds`

#### 🔧 Parameters
```
secret key type: sparse
poly modulus degree: 4096
log(q_0): 60
log(q_L): 222
log(p): 60
log(Q): 1602
log(scale): 51
log(delta): 60   // bootstrapping scale
d_0: 15
r: 11
bootstrapping_depth: 23
```
#### 🔐 ct_origin
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 1 (60) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ 0.4302616, 0.0005198, 0.0000073, 0.0025856, 0.0011213, 0.1254314, 0.0000508, 0.0944971, 0.0000216, 0.0009078, 0.0021641, 0.0013065, 0.0007961, 0.0001615, 0.2474095, 0.9994789, 0.3016986, 0.1049978, 0.0039519, 0.1307082, ..., 0.0524006, 0.0000715, 0.0110193, 0.0002005, 0.0504294, 0.2965176, 0.8779935, 0.0000315, 0.0403773, 0.3872134, 0.0000167, 0.0115504, 0.0002751, 0.0533847, 0.0098576, 0.2762847, 0.0173096, 0.2906318, 0.6575012, 0.0577668 ]
```
#### 🔁 ct_boot
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 3 (60 51 51) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ 0.4299062, 0.0009820, -0.0000295, 0.0026405, 0.0011299, 0.1254306, 0.0000777, 0.0945059, 0.0000308, 0.0009025, 0.0021401, 0.0013054, 0.0007832, 0.0001584, 0.2474131, 0.9994716, 0.3016845, 0.1049923, 0.0039229, 0.1307074, ..., 0.0524031, 0.0000709, 0.0110206, 0.0002008, 0.0504250, 0.2965516, 0.8779848, 0.0000169, 0.0403779, 0.3872150, 0.0000252, 0.0115454, 0.0002592, 0.0534030, 0.0098560, 0.2762934, 0.0173177, 0.2906207, 0.6575041, 0.0577807 ]
```

---

### Test 2

**Average Precision:** ≈ 2<sup>-17.4</sup>  
**Total Execution Time:** `173.744 seconds`

#### 🔧 Parameters
```
secret key type: sparse
poly modulus degree: 4096
log(q_0): 60
log(q_L): 222
log(p): 60
log(Q): 3522
log(scale): 51
log(delta): 120   // bootstrapping scale (high precision)
d_0: 31
r: 15
bootstrapping_depth: 55
```
#### 🔐 ct_origin
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 1 (60) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ 0.5342220, 0.2349046, 0.5738549, 0.4187213, 0.2661730, 0.0117234, 0.0166260, 0.4826129, 0.0000000, 0.0157543, 0.8626391, 0.2771124, 0.0077657, 0.1035753, 0.0132306, 0.2211003, 0.0982289, 0.0006923, 0.0000026, 0.6369750, ..., 0.1677940, 0.9198628, 0.0000336, 0.0234471, 0.0232711, 0.3340411, 0.0363127, 0.0002388, 0.2367894, 0.0023013, 0.0009073, 0.0044521, 0.0015939, 0.7264878, 0.0000251, 0.0619388, 0.0275279, 0.0299513, 0.2072166, 0.0122849 ]
```
#### 🔁 ct_boot
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 3 (60 51 51) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ 0.5326771, 0.2350106, 0.5738312, 0.4187149, 0.2661675, 0.0117274, 0.0166213, 0.4826144, 0.0000207, 0.0157597, 0.8626713, 0.2771086, 0.0077666, 0.1035732, 0.0132271, 0.2211053, 0.0982287, 0.0006859, 0.0000071, 0.6369720, ..., 0.1677956, 0.9198376, 0.0000166, 0.0234405, 0.0232664, 0.3340403, 0.0363129, 0.0002385, 0.2367931, 0.0022964, 0.0008992, 0.0044497, 0.0016032, 0.7264964, 0.0000329, 0.0619228, 0.0275337, 0.0299571, 0.2072197, 0.0123045 ]
```

</br>

---

### Test 3

**Average Precision:** ≈ 2<sup>-12.5</sup>  
**Total Execution Time:** `55.240 seconds`

#### 🔧 Parameters
```
secret key type: non-sparse
poly modulus degree: 4096
log(q_0): 60
log(q_L): 222
log(p): 60
log(Q): 1602
log(scale): 51
log(delta): 60   // bootstrapping scale
d_0: 15
r: 11
bootstrapping_depth: 23
```
#### 🔐 ct_origin
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 1 (60) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ 0.1704985, 0.0020546, 0.0223672, 0.1584157, 0.1128375, 0.0001254, 0.3193087, 0.4243500, 0.0001473, 0.3318937, 0.3397267, 0.7437012, 0.0002629, 0.1452058, 0.0299879, 0.0063979, 0.8799276, 0.4303158, 0.6986346, 0.0000043, ..., 0.0571956, 0.0037198, 0.3974817, 0.0544165, 0.0038632, 0.9753646, 0.0789867, 0.3782949, 0.2743226, 0.3388975, 0.0000000, 0.0000787, 0.1798915, 0.6624663, 0.0345304, 0.6539651, 0.1274846, 0.0299412, 0.3094168, 0.0053160 ]
```
#### 🔁 ct_boot
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 3 (60 51 51) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ 0.1663312, 0.0026589, 0.0222391, 0.1582627, 0.1128434, 0.0000877, 0.3192192, 0.4243507, 0.0000341, 0.3318521, 0.3397286, 0.7436859, 0.0002892, 0.1451749, 0.0299741, 0.0064717, 0.8799046, 0.4303067, 0.6985991, -0.0000700, ..., 0.0570278, 0.0036801, 0.3974438, 0.0544870, 0.0039390, 0.9753588, 0.0789742, 0.3783465, 0.2744098, 0.3389065, -0.0000582, 0.0001208, 0.1798911, 0.6624602, 0.0346773, 0.6539059, 0.1274500, 0.0299711, 0.3093078, 0.0052963 ]
```

### Test 4

**Average Precision:** ≈ 2<sup>-12.6</sup>  
**Total Execution Time:** `175.830 seconds`

#### 🔧 Parameters
```
secret key type: non-sparse
poly modulus degree: 4096
log(q_0): 60
log(q_L): 222
log(p): 60
log(Q): 3522
log(scale): 51
log(delta): 120   // bootstrapping scale (high precision)
d_0: 31
r: 15
bootstrapping_depth: 55
```
#### 🔐 ct_origin
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 1 (60) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ 0.0000005, 0.2498645, 0.0366183, 0.1448308, 0.1723640, 0.0186758, 0.0753285, 0.8891204, 0.0292172, 0.0629927, 0.6753175, 0.4464475, 0.0000105, 0.3652177, 0.0603656, 0.6202027, 0.0000000, 0.0563227, 0.9304839, 0.7576252, ..., 0.5399224, 0.0859459, 0.0097332, 0.9980895, 0.1406720, 0.0310311, 0.0281828, 0.2119306, 0.0001813, 0.0215433, 0.4223848, 0.0312257, 0.0048645, 0.0100773, 0.4579598, 0.2914993, 0.5467188, 0.9228084, 0.0768330, 0.1563164 ]
```
#### 🔁 ct_boot
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   coeff_modulus size: 3 (60 51 51) bits
|   scale: 2.2518e+15 (52 bits)
|   ciphertext size: 2
|   [ -0.0025340, 0.2488715, 0.0376607, 0.1446073, 0.1721090, 0.0186921, 0.0752548, 0.8891037, 0.0292037, 0.0629521, 0.6753351, 0.4464669, 0.0000500, 0.3652382, 0.0604021, 0.6201478, 0.0001044, 0.0563355, 0.9303806, 0.7576388, ..., 0.5399197, 0.0859415, 0.0097328, 0.9981358, 0.1406660, 0.0310061, 0.0281271, 0.2119373, 0.0001302, 0.0216292, 0.4222588, 0.0312461, 0.0048723, 0.0100652, 0.4579245, 0.2915450, 0.5466119, 0.9228028, 0.0768114, 0.1562934 ]
```

</br>

# 4. Example Code
### 1. test.cpp
```cpp
#include "ckks_bootstrapping_test.h"
#include "modules/io/printformat.h"
#include <random>

using namespace seal;
using namespace seal::util;
using namespace std;

int main()
{
    // Parameters.
    size_t poly_modulus_degree = 512;
    size_t slot_count = poly_modulus_degree >> 1;
    int q_0 = 60;
    int q_1 = 0;
    int q_l = q_0 + q_1;
    int p = q_l > 60 ? 60 : q_l;
    size_t l = 0;
    int scale_bit = 49;
    int delta_bit = 60;
    size_t d_0 = 15;
    size_t r = 11;
    size_t bootstrapping_depth = CKKSBootstrapper::get_bootstrap_depth(delta_bit, l, d_0, r);
    vector<int> coeff_modulus = CKKSBootstrapper::create_coeff_modulus({ q_0, scale_bit, scale_bit, p }, scale_bit, delta_bit, l, d_0, r);
    double_t scale = pow(2.0, scale_bit);
    double_t delta = pow(2.0, delta_bit);

    // CKKS context.
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_bootstrapping_depth(bootstrapping_depth);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_modulus));
    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;
    
    // Keys.
    KeyGenerator keygen(context, true);   // use sparse secret key.
    //KeyGenerator keygen(context);         // use non-sparse secret key.
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // Algorithms.
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    CKKSBootstrapper bootstrapper(context);   // create bootstrapper instance.

    // Random data.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    vector<complex<double_t>> vector_1, res_vector;
    vector_1.reserve(slot_count);
    for (size_t i = 0; i < slot_count; i++)
    {
        vector_1.push_back({ static_cast<double_t>(dist(gen)) });
        //vector_1.push_back({ static_cast<double_t>(dist(gen)) * 10 });
    }
    cout << "Input vector: " << endl;
    print_vector(vector_1, 3, 7);

    Plaintext plain_1, plain_res;
    encoder.encode(vector_1, scale, plain_1);

    Ciphertext cipher_1, cipher_res;
    encryptor.encrypt(plain_1, cipher_1);
    print_ciphertext<double_t>(context, cipher_1, encoder, decryptor, 20, 7);
    
    // Evaluate (ct^4).
    evaluator.square_inplace(cipher_1);
    evaluator.relinearize_inplace(cipher_1, relin_keys);
    evaluator.rescale_to_next_inplace(cipher_1);
    evaluator.square_inplace(cipher_1);
    evaluator.relinearize_inplace(cipher_1, relin_keys);
    evaluator.rescale_to_next_inplace(cipher_1);
    print_ciphertext<double_t>(context, cipher_1, encoder, decryptor, 20, 7);

    // Bootstrap.
    bootstrapper.bootstrapping(cipher_1, encoder, encryptor, evaluator, relin_keys, galois_keys, scale_bit, delta_bit, l, d_0, r, cipher_res, true);
    print_ciphertext<double_t>(context, cipher_res, encoder, decryptor, 20, 7);

    return 0;
}
```

</br>

# 5. References

### 1. Homomorphic Encryption for Arithmetic of Approximate Numbers
* https://eprint.iacr.org/2016/421.pdf

### 2. A Full RNS Variant of Approximate Homomorphic Encryption
* https://eprint.iacr.org/2018/931.pdf

### 3. Secure Outsourced Matrix Computation and Application to Neural Networks
* https://eprint.iacr.org/2018/1041.pdf

### 4. Bootstrapping for Approximate Homomorphic Encryption
* https://eprint.iacr.org/2018/153.pdf

### 5. Improved Bootstrapping for Approximate Homomorphic Encryption
* https://eprint.iacr.org/2018/1043.pdf

