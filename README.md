# Microsoft SEAL-Bootstrapping 2.0

This project provides an implementation of CKKS bootstrapping based on Microsoft SEAL.
Both non-sparse and sparse secret key variants are supported.

**In version 2.0**, the non-sparse key variant achieves `16~17 bits` of precision with a runtime of `31~34 seconds`, while the sparse key variant shows similar precision with a faster runtime of `26~28 seconds`.
Compared to version 1.x, this reflects an improvement of approximately `6~7 bits` in precision and a `39~53%` reduction in runtime. Detailed results can be found in the [Test](#2-test) section.
> (Note: We previously claimed a precision of 12~17 bits due to a calculation error, although the actual precision was around 10 bits. We apologize for the mistake.)

The bootstrapping process consists of the following core steps:
- Modulus reduction (q<sub>l</sub> -> q<sub>0</sub>)
- Modulus raising (q<sub>0</sub> -> Q)
- Coefficient-to-Slot using BSGS (CTS) 
- Approximate modulus reduction using Taylor series (Eval Mod q<sub>0</sub>) 
- Slot-to-Coefficient using BSGS (STC)
After bootstrapping, a ciphertext at level q<sub>L</sub> is obtained.

This code is designed for testing and analyzing the CKKS bootstrapping pipeline with configurable parameters and performance measurements.

**For any inquiries or feedback, please use the GitHub Issues tab or contact us at:**
> **Email: [`java_script@kakao.com`](java_script@kakao.com)**

</br>

# Contents
- [`Implementation`](#1-implementation)
- [`Test`](#2-test)
- [`Example Code`](#3-example-code)
- [`References`](#4-references)

</br>

# 1. Implementation

### 1) CKKSBootstrapper
- Provides CKKS bootstrapping operations to refresh and reduce noise in CKKS ciphertexts.
- Implements core functions for bootstrapping, including modulus extension, CTS, STC, approximate modulus reduction, and correction factor, among others.
- Source files:
  - [`CKKSBootstrapper.h`](/native/src/seal/bootstrapper.h)
  - [`CKKSBootstrapper.cpp`](/native/src/seal/bootstrapper.cpp)

### 2) Base conversion
- Fast/Exact base conversion.
- Source files:
  - [`rns.h`](/native/src/seal/util/rns.h)
  - [`rns.cpp`](/native/src/seal/util/rns.cpp)
    
### 3) Modulus raising
- Raises the modulus of a ciphertext to the highest (bootstrapping) modulus level in the modulus switching chain.
- Source files:
  - [`evaluator.h`](/native/src/seal/evaluator.h)
  - [`evaluator.cpp`](/native/src/seal/evaluator.cpp)

### 4) Validate parameters
- Validate or set the bootstrapping depth based on circuit parameters.
- Source files:
  - [`encryptionparams.h`](/native/src/seal/encryptionparams.h)
  - [`encryptionparams.cpp`](/native/src/seal/encryptionparams.cpp)

### 5) Context
- Defines entry_context and entry_parms_id.
- Checks whether the encryption parameters are secure under the HomomorphicEncryption.org security standard, taking bootstrapping depth into account.
- Creates an RNSTool instance required for bootstrapping.
- Source files:
  - [`context.h`](/native/src/seal/context.h)
  - [`context.cpp`](/native/src/seal/context.cpp)

### 6) Keygenerator
- Allows generating a sparse secret key (h = 64) using additional parameters.
- Source files:
  - [`keygenerator.h`](/native/src/seal/keygenerator.h)
  - [`keygenerator.cpp`](/native/src/seal/keygenerator.cpp)

### 7) Precision Evaluation Function
- Computes precision by decrypting ct<sub>origin</sub> and ct<sub>boot</sub>, then measuring the average error between the resulting vectors.
- Source files:
  - [`calc_precision.py`](/bootstrapping_test/calc_precision.py)
 
</br>

# 2. Test

### 1) Test Environment
- CPU: Intel Core i5-8500 @ 3.00GHz
- RAM: 32 GB
- OS: Windows 11 Pro (Version 24H2, Build 26100.4349)
- Architecture: 64-bit, x64-based processor
- Compiler: Microsoft Visual Studio (MSVC), C++17
- Build Configuration: Release

</br>

### 2) Test Summary

| Test      | Secret Key    | d_0    | r      |log<sub>2</sub>(N)|log<sub>2</sub>(q<sub>0</sub>) | log<sub>2</sub>(Q) | log<sub>2</sub>(scale) | log<sub>2</sub>(Δ) | Depth<sub>boot</sub> | Precision | Time (s) |
|-----------|---------------|--------|--------|--------|--------|--------|--------|--------|----------------------|--------------------|----------|
| Test 1    | Non-Sparse    | 15     | 11     | 12     | 60   | 1602   | 51   | 60   | 23                   | ≈2<sup>-16.78</sup> | 34.797  |
| Test 2    | Non-Sparse    | 15     | 9      | 12     | 60   | 1482   | 51   | 60   | 21                   | ≈2<sup>-17.08</sup> | 31.145  |
| Test 3    | Sparse (h=64) | 15     | 7      | 12     | 60   | 1362   | 51   | 60   | 19                   | ≈2<sup>-16.43</sup> | 28.234  |
| Test 4    | Sparse (h=64) | 15     | 6      | 12     | 60   | 1302   | 51   | 60   | 18                   | ≈2<sup>-16.64</sup> | 26.971  |

</br>

### 3) Test Results

- [`Test1 details`](/bootstrapping_test/MS_SEAL_Boot_2.0_non_sparse_r11.txt)
- [`Test2 details`](/bootstrapping_test/MS_SEAL_Boot_2.0_non_sparse_r9.txt)
- [`Test3 details`](/bootstrapping_test/MS_SEAL_Boot_2.0_sparse_r7.txt)
- [`Test4 details`](/bootstrapping_test/MS_SEAL_Boot_2.0_sparse_r6.txt)

</br>

# 3. Example Code
### 1. test.cpp
```cpp
#include <seal/seal.h>
#include <random>

using namespace seal;
using namespace std;

int main()
{
    // Parameters.
    size_t poly_modulus_degree = 4096;
    int q_0_bit_size = 60;
    int P_bit_size = q_0_bit_size;
    int scale_bit_size = 51;
    int delta_bit_size = 60;
    double_t scale = pow(2.0, scale_bit_size);
    double_t delta = pow(2.0, delta_bit_size);
    size_t encrypted_level = 0;
    size_t d_0 = 15;
    size_t r = 9;


    // CKKS context.
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_bootstrapping_depth(CKKSBootstrapper::get_bootstrap_depth(delta_bit_size, encrypted_level, d_0, r)); 
    parms.set_coeff_modulus(CKKSBootstrapper::create_coeff_modulus(   // create coefficient modulus for bootstrapping.
		poly_modulus_degree, 
        { q_0_bit_size, scale_bit_size, scale_bit_size, P_bit_size }, 
        delta_bit_size, encrypted_level, d_0, r));
    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;


    // Keys.
    //KeyGenerator keygen(context, true);   // use sparse secret key.
    KeyGenerator keygen(context);         // use non-sparse secret key.
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
	keygen.create_galois_keys(   // create Galois keys for bootstrapping.
        CKKSBootstrapper::create_galois_steps(poly_modulus_degree), galois_keys);


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
    vector_1.reserve(encoder.slot_count());
    for (size_t i = 0; i < encoder.slot_count(); i++)
    {
        vector_1.push_back({ static_cast<double_t>(dist(gen)) });
        //vector_1.push_back({ static_cast<double_t>(dist(gen)) * 10 });
    }
    cout << "Input vector: " << endl;
    print_vector(vector_1, 3, 7);

    Plaintext plain_1, plain_res;
    encoder.encode(vector_1, scale, plain_1);
    //encoder.encode(complex<double>(1, 1), scale, plain_1);

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
    print_ciphertext<double_t>(context, cipher_1, encoder, decryptor, encoder.slot_count(), 15);


    // Bootstrap.
    bootstrapper.bootstrapping(cipher_1, encoder, evaluator, relin_keys, galois_keys, delta_bit_size, encrypted_level, d_0, r, cipher_res, true);
    print_ciphertext<double_t>(context, cipher_res, encoder, decryptor, encoder.slot_count(), 15);


    return 0;
}
```

</br>

# 4. References

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

