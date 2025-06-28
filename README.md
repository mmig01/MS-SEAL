# Example Code

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
    size_t poly_modulus_degree = 4096;
    size_t slot_count = poly_modulus_degree >> 1;
    int q0 = 18;
    int l = 2;
    int scale_bit = 50;
    int delta_bit = 60;
    int d_0 = 7;
    int r = 10;
    int p = (q0 * (l + 1)) > 60 ? 60 : (q0 * (l + 1));
    size_t bootstrapping_depth = 0;
    double_t scale = pow(2.0, scale_bit);
    double_t delta = pow(2.0, delta_bit);

    // CKKS context
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree,
        CKKSBootstrapper::create_coeff_modulus({ q0, q0, q0, scale_bit, scale_bit, scale_bit, p }, scale_bit, delta_bit, l, d_0, r, bootstrapping_depth)
    ));
    parms.set_bootstrapping_depth(bootstrapping_depth);
    SEALContext context(parms);
    print_parameters(context); 
    cout << endl;

    // Keys
    KeyGenerator keygen(context);
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
       // input.push_back(static_cast<double_t>(i));//1073732609 * 1073738753, 134210561 * 134215681, 34359720961*34359724033
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
    print_ciphertext(context, cipher_1, decryptor, encoder);

    // bootstrap
    bootstrapper.bootstrapping(cipher_1, encoder, encryptor, evaluator, relin_keys, galois_keys, scale_bit, delta_bit, l, d_0, r, cipher_res);
    print_ciphertext(context, cipher_res, decryptor, encoder);

    return 0;
}
```