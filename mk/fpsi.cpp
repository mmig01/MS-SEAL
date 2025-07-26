#include "fpsi.h"

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

    EncryptionParameters context_param(scheme_type::bgv);

    uint64_t poly_modulus_degree = pow(2, 16); // 65536
    context_param.set_poly_modulus_degree(poly_modulus_degree);
    context_param.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 30));

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

    // #0. threshold 에 따른 Group 설정
    // G : Zp* 사용
    // g 는 Sender, receiver 모두에게 알려진 값
    int64_t threshold = 10;
    cout << "Threshold: " << threshold << endl;

    // NOTE: switched from 64-bit group element to 128-bit group element
    uint64_t group_generator = generator();          // g ∈ Z_P128^*
    cout << "Global group value g: " << group_generator << endl;

    // 미리 [g^(-threshold^2), ... g^(threshold^2)] 를 생성
    // NOTE: group_vector_square_threshold now holds u128 elements
    vector<uint64_t> group_vector_square_threshold;
    for (int64_t i = - (threshold * threshold); i <= (threshold * threshold); i++) {
        uint64_t exp = i;
        uint64_t val = group_arithmetic(group_generator, exp);
        group_vector_square_threshold.push_back(val);
    }

    // #1. Sender vector 생성
    // 총 두 개의 벡터를 생성
    // 1. sender_vector : a1 + a2·x + a3·x^2 + a4·x^3.. + ai·x^i (i 는 벡터 크기 - 1, 즉 마지막 항) 로 인코딩할 벡터
    // 2. 0 + 0·x + 0·x^2 + 0·x^3.. + (a1^2 + a2^2 + a3^2 + ... + ai^2)·x^i (i 는 벡터 크기 - 1, 즉 마지막 항) 로 인코딩할 벡터
    // sender vector : {1, 1, ... , 1}
    vector<int64_t> sender_vector;
    uint64_t set_vector_size = pow(2, 16); // 65536
    for (size_t i = 0; i < set_vector_size; i++) {
        // int64_t random_value = random_Zp(3);
        int64_t random_value = 1; // 테스트용
        sender_vector.push_back(random_value);
    }

    cout << "Sender vector: ";
    for (size_t i = 0; i < 5; i++) {
        cout << sender_vector[i] << " ";
    }
    cout << "...";
    cout << endl;

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
        // int64_t random_value = random_Zp(3);
        int64_t random_value = 1; // 테스트용
        receiver_vector.push_back(random_value);
    }
    cout << "Receiver vector: ";
    for (size_t i = 0; i < 5; i++) {
        cout << receiver_vector[i] << " ";
    }
    cout << "...";
    cout << endl;

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
    
    // # 7-1 receiver 는 random value R <- Zt 로 이루어진 R 벡터 생성
    vector<int64_t> receiver_random_vector;
    for (size_t i = 0; i < set_vector_size; i++) {
        // NOTE: changed to 128-bit random value
        int64_t random_value = static_cast<int64_t>(random_Zp(context_param.plain_modulus().value()));
        receiver_random_vector.push_back(random_value);
    }

    // # 7-2 receiver 는 R 벡터를 인코딩
    Plaintext receiver_random_plaintext;
    encoder.encode(receiver_random_vector, receiver_random_plaintext);

    // #7-3 receiver 는 R 벡터를 기존 암호문에 덧셈
    evaluator.add_plain_inplace(multiplied_ciphertext, receiver_random_plaintext);

    // // temp: random 값 출력
    // cout << "Receiver random vector: " << receiver_random_vector[set_vector_size - 1] << endl;
    // cout << endl;

    // #8. decrypt
    Plaintext decrypted_plaintext;
    decryptor.decrypt(multiplied_ciphertext, decrypted_plaintext);

    // #9. decode
    vector<int64_t> decoded_result;
    encoder.decode(decrypted_plaintext, decoded_result);

    int64_t minkowski_distance = decoded_result[set_vector_size - 1];
    cout << "연산 후 얻은 Minkowski distance: " << minkowski_distance << endl;
    cout << endl;

    //# Fuzzy matching 로직 구현
    // G : (Zp, +) 사용
    // g 는 Sender, receiver 모두에게 알려진 값

    // #10. Sender 의 random value alpha <- Zp 선택 (p : 128 bit)
    uint64_t alpha = random_Zp();

    // g^alpha 계산
    uint64_t g_square_alpha = group_arithmetic(group_generator, alpha);

    // g^(alpha * minkowski_distance) 계산
    uint64_t g_alpha_minkowski = group_arithmetic(g_square_alpha, minkowski_distance);

    // 계산한 값을 receiver 에게 전송 (g^alpha, g^(alpha * minkowski_distance))
    uint64_t sender_to_receiver_g_alpha = g_square_alpha;
    uint64_t sender_to_receiver_g_alpha_minkowski = g_alpha_minkowski;

    // #11. Receiver : random value beta, gamma <- Zp
    uint64_t beta = random_Zp();
    uint64_t gamma = random_Zp();

    // g^(alpha * beta * R) 의 역원 계산
    uint64_t R_in_Zp = receiver_random_vector[set_vector_size - 1];
    uint64_t g_alpha_beta_R = group_arithmetic(group_arithmetic(sender_to_receiver_g_alpha, beta), R_in_Zp);
    uint64_t inv_g_alpha_beta_R = mod_inv(g_alpha_beta_R);

    // g^(minkowski_distance * beta + gamma) 계산
    uint64_t g_minkowski_beta = group_arithmetic(sender_to_receiver_g_alpha_minkowski, beta);
    uint64_t g_gamma = group_arithmetic(group_generator, gamma);
    uint64_t g_minkowski_beta_gamma = mod_mul(g_minkowski_beta, g_gamma);

    // receiver 는 미리 생성해둔 group_vector_square_threshold 의 원소에 대해 g^(threshold^2 * alpha * beta + gamma) 를 계산
    vector<uint64_t> group_vector_square_threshold_using_hash;
    for (size_t i = 0; i < group_vector_square_threshold.size(); i++) {
        uint64_t temp = group_vector_square_threshold[i];
        uint64_t exponent = group_arithmetic(group_arithmetic(temp, alpha), beta);
        exponent = mod_mul(exponent, g_gamma);
        // 넣을 때는 hash 해서 넣어야 함! 지금은 그냥 평문
        group_vector_square_threshold_using_hash.push_back(exponent);
    }

    // #12. Receiver -> Sender : g_minkowski_beta_gamma, inv_g_alpha_beta_R, group_vector_square_threshold_using_hash 전송
    uint64_t receiver_to_sender_g_minkowski_beta_gamma = g_minkowski_beta_gamma;
    uint64_t receiver_to_sender_inv_g_alpha_beta_R = inv_g_alpha_beta_R;
    vector<uint64_t> receiver_to_sender_group_vector_square_threshold_using_hash = group_vector_square_threshold_using_hash;

    // #13. Sender 는 receiver_to_sender_g_minkowski_beta_gamma * receiver_to_sender_inv_g_alpha_beta_R 를 수행 후, Fuzzy Matching 수행
    uint64_t fuzzy_matching_result = mod_mul(receiver_to_sender_g_minkowski_beta_gamma, receiver_to_sender_inv_g_alpha_beta_R);
    // uint64_t fuzzy_matching_result = receiver_to_sender_g_minkowski_beta_gamma;

    for (auto& element : receiver_to_sender_group_vector_square_threshold_using_hash) {
        if (fuzzy_matching_result == element) {
            cout << "Fuzzy Matching 성공! 일치하는 값: " << element << endl;
            break;
        }
    }

    // 시간 측정 종료 및 결과 출력
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = end_time - start_time;
    cout << "실행 시간: " << elapsed_time.count() << " 초" << endl;

    return 0;
}