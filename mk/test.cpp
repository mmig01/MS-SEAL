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

    uint64_t poly_modulus_degree = 1024;
    context_param.set_poly_modulus_degree(poly_modulus_degree);
    context_param.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 17));

    uint64_t result;
    util::try_minimal_primitive_root(poly_modulus_degree * 2, context_param.plain_modulus(), result);
    cout << "minimal primitive root:" << result << '\n';
    cout << "prime num:" << context_param.plain_modulus().value() << '\n';
    context_param.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 60, 60, 60, 60, 60 }));

    SEALContext context(context_param, true, sec_level_type::none);
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

    vector<int64_t> vt = { 1, 1, 1, 1, 1 };
    Plaintext pt;
    Ciphertext ct;

    encoder.encode(vt, pt);
    cout << "slot count: " << encoder.slot_count() << '\n';
    // encryptor.encrypt(pt, ct);
    // cout << "ct coef size:" << ct.coeff_modulus_size() << '\n';

    cout << "랄랄랄" << '\n';

    // for (int i = 0; i < 9; i++)
    // {
    //     evaluator.multiply_inplace(ct, ct);
    //     evaluator.relinearize_inplace(ct, relin_key);
    //     //evaluator.mod_switch_to_next_inplace(ct);
    //     cout << "ct coef size:" << ct.coeff_modulus_size() << '\n';
    // }


    // print_cipher_rns_coeff(ct, context, evaluator);

    // decryptor.decrypt(ct, pt);
    // encoder.decode(pt, vt);

    // for (size_t i = 0; i < 5; i++)
    // {
    //     cout << vt[i] << ' ';
    // }
    // cout << '\n';
    

}