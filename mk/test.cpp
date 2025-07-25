#include "test.h"

using namespace std;
using namespace seal;

int main(){
    
    // +----------------------------------------------------+
    // | poly_modulus_degree | max coeff_modulus bit-length |
    // +---------------------+------------------------------+
    // | 1024                | 27                           |
    // | 2048                | 54                           |
    // | 4096                | 109                          |
    // | 8192                | 218                          |
    // | 16384               | 438                          |
    // | 32768               | 881                          |
    // +---------------------+------------------------------+

    EncryptionParameters context_param(scheme_type::bfv);

    uint64_t poly_modulus_degree = 8192;
    context_param.set_poly_modulus_degree(poly_modulus_degree);
    context_param.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 17));

    // uint64_t result;
    // util::try_minimal_primitive_root(poly_modulus_degree * 2, context_param.plain_modulus(), result);
    // cout << "minimal primitive root:" << result << '\n';
    // cout << "prime num:" << context_param.plain_modulus().value() << '\n';

    context_param.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, 30, 30, 30, 30, 30 }));

    SEALContext context(context_param, true, sec_level_type::tc128);
    cout << context.first_context_data()->qualifiers().parameter_error_message() << '\n';

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_key;
    keygen.create_relin_keys(relin_key);

    BatchEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);

    vector<int64_t> q1 = { 1, 1, 1, 1, 1 };
    vector<int64_t> q2 = { 2, 2, 2, 2, 2 };
    vector<int64_t> q3 = { 3, 3, 3, 3, 3 };

    Plaintext pt1;
    Plaintext pt2;
    Plaintext pt3;

    Ciphertext ct1;
    Ciphertext ct2;
    Ciphertext ct3;

    encoder.encode(q1, pt1);
    encoder.encode(q2, pt2);
    encoder.encode(q3, pt3);

    cout << "slot count: " << encoder.slot_count() << '\n';
    
    encryptor.encrypt(pt1, ct1);
    auto delta = context.first_context_data()->coeff_div_plain_modulus();
    cout << "delta: " << delta << '\n';
    uint64_t q_mod_t = context.first_context_data()->coeff_modulus_mod_plain_modulus();
    cout << "q mod t: " << q_mod_t << '\n';

    encryptor.encrypt(pt2, ct2);
    encryptor.encrypt(pt3, ct3);


    evaluator.multiply_inplace(ct1, ct1);
    evaluator.relinearize_inplace(ct1, relin_key);
    
    evaluator.multiply_inplace(ct2, ct2);
    evaluator.relinearize_inplace(ct2, relin_key);

    evaluator.multiply_inplace(ct3, ct3);
    evaluator.relinearize_inplace(ct3, relin_key);

    decryptor.decrypt(ct1, pt1);
    decryptor.decrypt(ct2, pt2);
    decryptor.decrypt(ct3, pt3);

    encoder.decode(pt1, q1);
    encoder.decode(pt2, q2);
    encoder.decode(pt3, q3);

    for (size_t i = 0; i < 5; i++)
    {
        cout << q1[i] << ' ';
    }
    cout << '\n';

    for (size_t i = 0; i < 5; i++)
    {
        cout << q2[i] << ' ';
    }
    cout << '\n';

    for (size_t i = 0; i < 5; i++)
    {
        cout << q3[i] << ' ';
    }
    cout << '\n';

}