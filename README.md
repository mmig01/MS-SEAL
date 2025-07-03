# 1. Abstract

This project provides an implementation of CKKS bootstrapping based on Microsoft SEAL.
Both sparse and non-sparse secret key variants are supported.

The bootstrapping process consists of the following core steps:
- Modulus raising (q_l -> Q)
- Coefficient-to-Slot using BSGS (CTS) 
- Approximate modulus reduction using Taylor series (EvalMod) 
- Slot-to-Coefficient using BSGS (STC) 

This code is designed for testing and analyzing the CKKS bootstrapping pipeline with configurable parameters and performance measurements.

</br>

# 2. Test Result

### 1. Using Sparse Secret-key
**Total Execute Time:** `58.711 seconds`
#### 🔧 Parameters
```
poly modulus degree: 4096
log(q_0): 60
log(q_L): 270
log(p): 60
log(Q): 1650
log(scale): 50
log(delta): 60
d_0: 15
r: 11
bootstrapping_depth: 23
```
#### 🔐 ct_origin
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   scale: 1.1259e+15 (50 bit)
|   ciphertext size: 2
|   coeff_modulus size: 2 (60 50) bits

[ 0.087019893020001, 0.012219522347132, 0.558087017341350, 0.627927660756643, 0.060294743107597, 0.015303185387800, 0.010326633193835, ..., 0.920859662621363, 0.028480650949390, 0.001499326123227, 0.000014956083973, 0.115591626778099, 0.006475732386272, 0.000304616490808 ]
```
#### 🔁 ct_boot
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   scale: 1.1259e+15 (50 bit)
|   ciphertext size: 2
|   coeff_modulus size: 4 (60 50 50 50) bits

[ 0.087255359950414, 0.012153033674326, 0.557874756214800, 0.627937690376493, 0.060284428142563, 0.015326010449825, 0.010358470461282, ..., 0.920860675947827, 0.028468673577842, 0.001505264937569, 0.000009655515811, 0.115570764942649, 0.006492453288252, 0.000285911392471 ]
```

</br>

---
### 2. Using non-sparse secret-key
**Total Execute Time:** `58.711 seconds`
#### 🔧 Parameters
```
poly modulus degree: 4096
log(q_0): 60
log(q_L): 270
log(p): 60
log(Q): 1770
log(scale): 50
log(delta): 60
d_0: 15
r: 13
bootstrapping_depth: 25
```
#### 🔐 ct_origin
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   scale: 1.1259e+15 (50 bit)
|   ciphertext size: 2
|   coeff_modulus size: 2 (60 50) bits

[ 0.154946322722986, 0.009506084596152, 0.004798507971306, 0.413075071219107, 0.667867070071345, 0.005850478029126, 0.591066307154725, ..., 0.168591960474894, 0.191589225163427, 0.978196608502135, 0.000000117384576, 0.227566471573945, 0.855920747945947, 0.163855464797658 ]
```
#### 🔁 ct_boot
```
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 4096
|   scale: 1.1259e+15 (50 bit)
|   ciphertext size: 2
|   coeff_modulus size: 4 (60 50 50 50) bits

[ 0.154981414889782, 0.009472785164953, 0.004799962967103, 0.413072354801908, 0.667868961879702, 0.005863059168285, 0.591066253181384, ..., 0.168592275605554, 0.191589135149281, 0.978196239534389, -0.000002704793360, 0.227567981473021, 0.855920464696435, 0.163856940786023 ]
```

</br>

# 3. Example Code

```cpp
#include "ckks_bootstrapping_test.h"
#include "modules/io/printformat.h"
#include <random>

using namespace seal;
using namespace seal::util;
using namespace std;

int main()
{
    // Parameters
    size_t poly_modulus_degree = 8192;
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
    size_t bootstrapping_depth = CKKSBootstrapper::get_bootstrap_depth(l, d_0, r);
    vector<int> coeff_modulus = CKKSBootstrapper::create_coeff_modulus({ q_0, scale_bit, scale_bit, p }, scale_bit, delta_bit, l, d_0, r);
    double_t scale = pow(2.0, scale_bit);
    double_t delta = pow(2.0, delta_bit);

    // CKKS context
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_bootstrapping_depth(bootstrapping_depth);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_modulus));
    SEALContext context(parms, true, sec_level_type::tc128);
    print_parameters(context);
    cout << endl;
    
    // Keys
    KeyGenerator keygen(context, true);   // true: use sparse key, false or omitted: use non-sparse key
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // Algorithms
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    CKKSBootstrapper bootstrapper(context);

    // Random data
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
    print_ciphertext(context, cipher_1, decryptor, encoder);
    
    // evaluate
    evaluator.square_inplace(cipher_1);
    evaluator.relinearize_inplace(cipher_1, relin_keys);
    evaluator.rescale_to_next_inplace(cipher_1);

    evaluator.square_inplace(cipher_1);
    evaluator.relinearize_inplace(cipher_1, relin_keys);
    evaluator.rescale_to_next_inplace(cipher_1);

    print_ciphertext(context, cipher_1, decryptor, encoder);

    // bootstrap
    bootstrapper.bootstrapping(cipher_1, encoder, encryptor, evaluator, relin_keys, galois_keys, scale_bit, delta_bit, l, d_0, r, cipher_res);
    print_ciphertext(context, cipher_res, decryptor, encoder);

    return 0;
}
```