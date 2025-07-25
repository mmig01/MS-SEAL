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

    uint64_t poly_modulus_degree = pow(2, 17); // 131072
    context_param.set_poly_modulus_degree(poly_modulus_degree);
    context_param.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 49));

    context_param.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(context_param, true, sec_level_type::none);
    cout << context.first_context_data()->qualifiers().parameter_error_message() << '\n';
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_key;
    keygen.create_relin_keys(relin_key);

    CoeffEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);

    // #1. Sender vector 생성
    // 총 두 개의 벡터를 생성
    // 1. sender_vector : a1 + a2·x + a3·x^2 + a4·x^3.. + ai·x^i (i 는 벡터 크기 - 1, 즉 마지막 항) 로 인코딩할 벡터
    // 2. 0 + 0·x + 0·x^2 + 0·x^3.. + (a1^2 + a2^2 + a3^2 + ... + ai^2)·x^i (i 는 벡터 크기 - 1, 즉 마지막 항) 로 인코딩할 벡터
    // sender vector : {1, 1, ... , 1}
    vector<int64_t> sender_vector;
    uint64_t set_vector_size = pow(2, 16); // 65536
    for (size_t i = 0; i < set_vector_size; i++) {
        sender_vector.push_back(1);
    }

    // sender vector square : // {0, 0, ... , 0, a1^2 + a2^2 + a3^2 + ... + ai^2}
    vector<int64_t> sender_vector_square;
    uint64_t temp = 0;
    for (size_t i = 0; i < set_vector_size; i++) {
        temp += sender_vector[i] * sender_vector[i];
        if (i == set_vector_size - 1) {
            sender_vector_square.push_back(temp);
        } else {
            sender_vector_square.push_back(0);
        }
    }

    // #2. Sender vector encoding
    // ex) a1 + a2·x + a3·x^2 + a4·x^3 + a5·x^4 ...
    // ex) 0 + 0·x + 0·x^2 + 0·x^3 + (a1^2 + a2^2 + a3^2 + ... + ai^2)·x^i
    // sender vector = { a11, a12, a13, a14, a15 };

    Plaintext sender_plaintext;
    Plaintext sender_square_plaintext;

    encoder.encode(sender_vector, sender_plaintext);
    encoder.encode(sender_vector_square, sender_square_plaintext);

    // #3. Sender vector를 encrypt
    Ciphertext sender_ciphertext;
    Ciphertext sender_square_ciphertext;
    encryptor.encrypt(sender_plaintext, sender_ciphertext);
    encryptor.encrypt(sender_square_plaintext, sender_square_ciphertext);

    //#4. Receiver vector 생성 후, 순서 반전
    // 마찬가지로 receiver vector, receiver vector square 생성
    vector<int64_t> receiver_vector;
    for (size_t i = 0; i < set_vector_size; i++) {
        receiver_vector.push_back(2);
    }

    // 순서 반전
    for (size_t i = 0; i < set_vector_size / 2; i++) {
        swap(receiver_vector[i], receiver_vector[set_vector_size - 1 - i]);
    }

    vector<int64_t> receiver_vector_square;
    temp = 0;
    for (size_t i = 0; i < set_vector_size; i++) {
        temp += receiver_vector[i] * receiver_vector[i];
        if (i == set_vector_size - 1) {
            receiver_vector_square.push_back(temp);
        } else {
            
            receiver_vector_square.push_back(0);
        }
    }

    // reveiver vector 원소에 -2 곱하기
    for (auto &value : receiver_vector) {
        value *= -2;
    }
    
    // #5. Receiver vector encoding
    Plaintext receiver_plaintext;
    encoder.encode(receiver_vector, receiver_plaintext);
    Plaintext receiver_square_plaintext;
    encoder.encode(receiver_vector_square, receiver_square_plaintext);

    // #6. Receiver vector encrypt
    Ciphertext receiver_ciphertext;
    Ciphertext receiver_square_ciphertext;
    encryptor.encrypt(receiver_plaintext, receiver_ciphertext);
    encryptor.encrypt(receiver_square_plaintext, receiver_square_ciphertext);

     // 여기서부터 시간 측정
    // 시간 측정 변수 선언
    chrono::high_resolution_clock::time_point start_time, end_time;
    chrono::duration<double> elapsed_time;
    start_time = chrono::high_resolution_clock::now();

    // #6. Sender -> Receiver 암호문 전송

    Ciphertext sender_to_receiver_ciphertext;
    Ciphertext sender_to_receiver_square_ciphertext;

    sender_to_receiver_ciphertext = sender_ciphertext;
    sender_to_receiver_square_ciphertext = sender_square_ciphertext;

    // #7. square 벡터는 단순 덧셈, 기본 벡터는 한 번 곱셈
    Ciphertext multiplied_ciphertext;
    evaluator.multiply(sender_to_receiver_ciphertext, receiver_ciphertext, multiplied_ciphertext);
    evaluator.relinearize_inplace(multiplied_ciphertext, relin_key);
   
    evaluator.add_inplace(multiplied_ciphertext, sender_to_receiver_square_ciphertext);
    evaluator.add_inplace(multiplied_ciphertext, receiver_square_ciphertext);
    
    // #8. decrypt
    Plaintext decrypted_plaintext;
    decryptor.decrypt(multiplied_ciphertext, decrypted_plaintext);

    // #9. decode
    vector<int64_t> decoded_result;
    encoder.decode(decrypted_plaintext, decoded_result);
    cout << "Decoded result: ";
    for (size_t i = 0; i < set_vector_size; i++) {
        cout << decoded_result[i] << " ";
    }
    cout << endl;
    // 시간 측정 종료 및 결과 출력
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = end_time - start_time;
    cout << "실행 시간: " << elapsed_time.count() << " 초" << endl;

}