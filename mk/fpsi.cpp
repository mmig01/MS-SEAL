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

    uint64_t poly_modulus_degree = pow(2, 16); // 2^16 = 65536
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
    uint64_t group_generator = generator();          // g Z*q 의 generator
    cout << "Global group value g: " << group_generator << endl;

    // 미리 [-threshold^2), ... threshold^2)] 를 생성
    vector<uint64_t> vector_square_threshold;
    for (int64_t i = - (threshold * threshold); i <= (threshold * threshold); i++) {
        vector_square_threshold.push_back(static_cast<uint64_t>(i));
    }

    // sender, receiver 의 전체 백터 개수
    uint64_t total_vector_cnt = 10;

    // #1. Sender vector 생성
    // 총 두 개의 벡터를 생성
    // 1. vector<vector<int64_t>> sender_vector : a1 + a2·x + a3·x^2 + a4·x^3.. + ai·x^i (i 는 벡터 크기 - 1, 즉 마지막 항) 로 인코딩할 벡터의 집합
    // 2. vector<vector<int64_t>> sender_vector_square : 0 + 0·x + 0·x^2 + 0·x^3.. + (a1^2 + a2^2 + a3^2 + ... + ai^2)·x^i (i 는 벡터 크기 - 1, 즉 마지막 항) 로 인코딩할 벡터의 집합
    // sender vector : {1, 1, ... , 1}
    vector<vector<int64_t>> sender_vector(total_vector_cnt);
    uint64_t set_vector_size = poly_modulus_degree;
    
    for (size_t j = 0; j < total_vector_cnt; j++) {
        vector<int64_t> sender_vector_element;
        for (size_t i = 0; i < set_vector_size; i++) {
            int64_t random_value = 0;
            // 테스트로 다섯 군데 값 넣기
            if (j == 0 && (i == 1 || i == 3 || i == 5 || i == 7 || i == 9)) {
                random_value = random_Zp(3);
            }
            sender_vector_element.push_back(random_value);
        }
        sender_vector[j] = sender_vector_element;
    }
    
    cout << "Sender vector: " << endl;
    for (size_t j = 0; j < total_vector_cnt; j++) {
        cout << "Vector " << j << ": ";
        for (size_t i = 0; i < 10; i++) {
            cout << sender_vector[j][i] << " ";
        }
        cout << endl;
    }

    // sender vector square : // {0, 0, ... , 0, a1^2 + a2^2 + a3^2 + ... + ai^2}
    vector<vector<int64_t>> sender_vector_square(total_vector_cnt);
    for (size_t j = 0; j < total_vector_cnt; j++) {
        uint64_t temp = 0;
        vector<int64_t> sender_vector_square_element;
        for (size_t i = 0; i < set_vector_size; i++) {
            temp += sender_vector[j][i] * sender_vector[j][i];
            if (i == set_vector_size - 1) {
                sender_vector_square_element.push_back(temp);
            } else {
                sender_vector_square_element.push_back(0);
            }
        }
        sender_vector_square[j] = sender_vector_square_element;
    }
    

    // #2. Sender vector encoding
    // ex) a1 + a2·x + a3·x^2 + a4·x^3 + a5·x^4 ...
    // ex) 0 + 0·x + 0·x^2 + 0·x^3 + (a1^2 + a2^2 + a3^2 + ... + ai^2)·x^i
    // sender vector = { a11, a12, a13, a14, a15 };

    vector<Plaintext> sender_plaintext(total_vector_cnt);
    vector<Plaintext> sender_square_plaintext(total_vector_cnt);

    for (size_t j = 0; j < total_vector_cnt; j++) {
        encoder.encode(sender_vector[j], sender_plaintext[j]);
        encoder.encode(sender_vector_square[j], sender_square_plaintext[j]);
    }

    // #3. Sender vector를 encrypt
    vector<Ciphertext> sender_ciphertext(total_vector_cnt);
    vector<Ciphertext> sender_square_ciphertext(total_vector_cnt);
    for (size_t j = 0; j < total_vector_cnt; j++) {
        encryptor.encrypt(sender_plaintext[j], sender_ciphertext[j]);
        encryptor.encrypt(sender_square_plaintext[j], sender_square_ciphertext[j]);
    }

    //#4. Receiver vector 생성 후, 순서 반전
    // 마찬가지로 receiver vector, receiver vector square 생성
    vector<vector<int64_t>> receiver_vector(total_vector_cnt);
    for (size_t j = 0; j < total_vector_cnt; j++) {
        vector<int64_t> receiver_vector_element;
        for (size_t i = 0; i < set_vector_size; i++) {
            int64_t random_value = 0;
            if (j == 0 && (i == 0 || i == 2 || i == 4 || i == 6 || i == 8)) {
                // 테스트로 다섯 군데 값 넣기
                random_value = random_Zp(3);
            }
            receiver_vector_element.push_back(random_value);
        }
        receiver_vector[j] = receiver_vector_element;
    }

    cout << "Receiver vector: " << endl;
    for (size_t j = 0; j < total_vector_cnt; j++) {
        cout << "Vector " << j << ": ";
        for (size_t i = 0; i < 10; i++) {
            cout << receiver_vector[j][i] << " ";
        }
        cout << endl;
    }

    // 순서 반전
    for (size_t j = 0; j < total_vector_cnt; j++) {
        for (size_t i = 0; i < set_vector_size / 2; i++) {
            swap(receiver_vector[j][i], receiver_vector[j][set_vector_size - 1 - i]);
        }
    }

    vector<vector<int64_t>> receiver_vector_square(total_vector_cnt);
    for (size_t j = 0; j < total_vector_cnt; j++) {
        vector<int64_t> receiver_vector_square_element;
        int64_t temp = 0;
        for (size_t i = 0; i < receiver_vector[j].size(); i++) {
            temp += receiver_vector[j][i] * receiver_vector[j][i];
            if (i == receiver_vector[j].size() - 1) {
                receiver_vector_square_element.push_back(temp);
            } else {
                receiver_vector_square_element.push_back(0);
            }
        }
        receiver_vector_square[j] = receiver_vector_square_element;
    }


    // reveiver vector 원소에 -2 곱하기
    for (size_t j = 0; j < total_vector_cnt; j++) {
        for (size_t i = 0; i < set_vector_size; i++) {
            receiver_vector[j][i] *= -2;
        }
    }
    
    // #5. Receiver vector encoding
    vector<Plaintext> receiver_plaintext(total_vector_cnt);
    vector<Plaintext> receiver_square_plaintext(total_vector_cnt);
    for (size_t j = 0; j < total_vector_cnt; j++) {
        encoder.encode(receiver_vector[j], receiver_plaintext[j]);
        encoder.encode(receiver_vector_square[j], receiver_square_plaintext[j]);
    }

    // #6. Receiver vector encrypt
    vector<Ciphertext> receiver_ciphertext(total_vector_cnt);
    vector<Ciphertext> receiver_square_ciphertext(total_vector_cnt);
    for (size_t j = 0; j < total_vector_cnt; j++) {
        encryptor.encrypt(receiver_plaintext[j], receiver_ciphertext[j]);
        encryptor.encrypt(receiver_square_plaintext[j], receiver_square_ciphertext[j]);
    }

    // 여기서부터 시간 측정
    // 시간 측정 변수 선언
    chrono::high_resolution_clock::time_point start_time, end_time;
    chrono::duration<double> elapsed_time;
    start_time = chrono::high_resolution_clock::now();

    // #6. Sender -> Receiver 암호문 전송

    vector<Ciphertext> sender_to_receiver_ciphertext(total_vector_cnt);
    vector<Ciphertext> sender_to_receiver_square_ciphertext(total_vector_cnt);

    for (size_t j = 0; j < total_vector_cnt; j++) {
        sender_to_receiver_ciphertext[j] = sender_ciphertext[j];
        sender_to_receiver_square_ciphertext[j] = sender_square_ciphertext[j];
    }

    // #7. sender 와 receiver 의 암호문 연산
    // square 벡터는 단순 덧셈, 기본 벡터는 한 번 곱셈
    vector<vector<Ciphertext>> multiplied_ciphertext(total_vector_cnt);
    for (size_t sender_cnt = 0; sender_cnt < total_vector_cnt; sender_cnt++) {
        vector<Ciphertext> multiplied_ciphertext_element(total_vector_cnt);
        for (size_t receiver_cnt = 0; receiver_cnt < total_vector_cnt; receiver_cnt++) {
            evaluator.multiply(sender_to_receiver_ciphertext[sender_cnt], receiver_ciphertext[receiver_cnt], multiplied_ciphertext_element[receiver_cnt]);
            evaluator.relinearize_inplace(multiplied_ciphertext_element[receiver_cnt], relin_key);

            evaluator.add_inplace(multiplied_ciphertext_element[receiver_cnt], sender_to_receiver_square_ciphertext[sender_cnt]);
            evaluator.add_inplace(multiplied_ciphertext_element[receiver_cnt], receiver_square_ciphertext[receiver_cnt]);
        }
        multiplied_ciphertext[sender_cnt] = multiplied_ciphertext_element;
    }
            
    // # 7-1 receiver 는 random value R <- Zt 로 이루어진 random 벡터 생성
    // 일단 모두 같은 R 을 사용 하지만, 추후 수정 해야 함.
    vector<uint64_t> receiver_random_vector;
    for (size_t i = 0; i < set_vector_size; i++) {
        uint64_t random_value = random_Zp(context_param.plain_modulus().value());
        receiver_random_vector.push_back(random_value);
    }
    
    // random 벡터의 마지막 값을 R 로 사용
    uint64_t R = receiver_random_vector[set_vector_size - 1];

    // vector_square_threshold 의 모든 원소에 R 을 더한 후, mod plain_modulus 연산
    for (size_t i = 0; i < vector_square_threshold.size(); i++) {
        vector_square_threshold[i] = (vector_square_threshold[i] + R) % context_param.plain_modulus().value();
    }

    // # 7-2 receiver 는 R 벡터를 인코딩
    Plaintext receiver_random_plaintext;
    encoder.encode(receiver_random_vector, receiver_random_plaintext);

    // #7-3 receiver 는 R 벡터를 기존 암호문에 덧셈
    for (size_t sender_cnt = 0; sender_cnt < total_vector_cnt; sender_cnt++) {
        for (size_t receiver_cnt = 0; receiver_cnt < total_vector_cnt; receiver_cnt++) {
            // sender 의 암호문에 R 벡터를 덧셈
            evaluator.add_plain_inplace(multiplied_ciphertext[sender_cnt][receiver_cnt], receiver_random_plaintext);
        }
    }

    // #8. decrypt
    vector<vector<Plaintext>> decrypted_plaintext(total_vector_cnt);
    for (size_t sender_cnt = 0; sender_cnt < total_vector_cnt; sender_cnt++) {
        vector<Plaintext> decrypted_plaintext_element(total_vector_cnt);
        for (size_t receiver_cnt = 0; receiver_cnt < total_vector_cnt; receiver_cnt++) {
            decryptor.decrypt(multiplied_ciphertext[sender_cnt][receiver_cnt], decrypted_plaintext_element[receiver_cnt]);
        }
        decrypted_plaintext[sender_cnt] = decrypted_plaintext_element;
    }

    // #9. decode
    vector<vector<vector<uint64_t>>> decoded_result(total_vector_cnt);

    for (size_t sender_cnt = 0; sender_cnt < total_vector_cnt; sender_cnt++) {
        vector<vector<uint64_t>> decoded_result_element(total_vector_cnt);
        for (size_t receiver_cnt = 0; receiver_cnt < total_vector_cnt; receiver_cnt++) {
            vector<uint64_t> decoded_vector;
            encoder.decode(decrypted_plaintext[sender_cnt][receiver_cnt], decoded_vector);
            decoded_result_element[receiver_cnt] = decoded_vector;
        }
        decoded_result[sender_cnt] = decoded_result_element;
    }

    vector<vector<int64_t>> minkowski_distances(total_vector_cnt);
    for (size_t sender_cnt = 0; sender_cnt < total_vector_cnt; sender_cnt++) {
        vector<int64_t> minkowski_distance_element(total_vector_cnt);
        for (size_t receiver_cnt = 0; receiver_cnt < total_vector_cnt; receiver_cnt++) {
            // 마지막 원소가 Minkowski distance
            int64_t minkowski_distance = decoded_result[sender_cnt][receiver_cnt][set_vector_size - 1];
            minkowski_distance_element[receiver_cnt] = minkowski_distance;
        }
        minkowski_distances[sender_cnt] = minkowski_distance_element;
    }
    
    // minkowski_distances 출력
    cout << "Minkowski distances:" << endl;
    for (size_t sender_cnt = 0; sender_cnt < total_vector_cnt; sender_cnt++) {
        for (size_t receiver_cnt = 0; receiver_cnt < total_vector_cnt; receiver_cnt++) {
            cout << "Sender " << sender_cnt << " to Receiver " << receiver_cnt << ": ";
            cout << minkowski_distances[sender_cnt][receiver_cnt] << " ";
            cout << endl;
        }
        cout << endl;
    }
    

    //# Fuzzy matching 로직 구현
    // total_vector_cnt X total_vector_cnt 의 Fuzzy Matching 수행
    for (size_t sender_cnt = 0; sender_cnt < total_vector_cnt; sender_cnt++) {
        for (size_t receiver_cnt = 0; receiver_cnt < total_vector_cnt; receiver_cnt++) {
            // Fuzzy Matching 수행
            // receiver 는 먼저 random value 𝛄 을 생성, g^𝛄 을 sender 에게 전송
            uint64_t gamma = random_Zp();
            uint64_t g_gamma = group_arithmetic(group_generator, gamma);

            // #10. Sender 는 receiver 에게 g^𝛄 을 받고,random value ⍺, β <- Zp 선택 (p : 128 bit), 
            uint64_t receiver_to_sender_g_gamma = g_gamma;
            uint64_t alpha = random_Zp();
            uint64_t beta = random_Zp();

            // g^⍺𝛄 계산
            uint64_t g_alpha_gamma = group_arithmetic(receiver_to_sender_g_gamma, alpha);

            // g^⍺, g^β 계산
            uint64_t g_alpha = group_arithmetic(group_generator, alpha);
            uint64_t g_beta = group_arithmetic(group_generator, beta);

            // g^(⍺ * minkowski_distance + β) 계산
            uint64_t g_alpha_minkowski_beta = mod_mul(group_arithmetic(g_alpha, minkowski_distances[sender_cnt][receiver_cnt]), g_beta);

            // 계산한 값을 receiver 에게 전송 (g^(⍺ * minkowski_distance + β), g^⍺𝛄)
            uint64_t sender_to_receiver_g_alpha_minkowski_beta = g_alpha_minkowski_beta;
            uint64_t sender_to_receiver_g_alpha_gamma = g_alpha_gamma;

            // #11. Receiver 의 random value s <- Zp
            uint64_t secret = random_Zp();

            // g^{(⍺ * minkowski_distance + β) * 𝛄 + s} 계산
            uint64_t g_alpha_minkowski_beta_gamma = group_arithmetic(sender_to_receiver_g_alpha_minkowski_beta, gamma);
            uint64_t g_secret = group_arithmetic(group_generator, secret);
            uint64_t g_alpha_minkowski_beta_gamma_secret = mod_mul(g_alpha_minkowski_beta_gamma, g_secret);

            // receiver 는 전달 받은 g^⍺𝛄 을 이용하여 vector_square_threshold 의 원소에 대해 g^(threshold^2 * ⍺ * 𝛄 + s) 를 계산
            vector<uint64_t> group_vector_square_threshold_using_hash;
            for (size_t i = 0; i < vector_square_threshold.size(); i++) {
                uint64_t exp = vector_square_threshold[i];
                uint64_t g_exp_alpha_gamma = group_arithmetic(sender_to_receiver_g_alpha_gamma, exp);
                uint64_t g_exp_alpha_gamma_secret = mod_mul(g_exp_alpha_gamma, g_secret);
            
                // 넣을 때는 hash 해서 넣어야 함! 지금은 그냥 평문
                group_vector_square_threshold_using_hash.push_back(g_exp_alpha_gamma_secret);
            }

            // #12. Receiver -> Sender : g^{⍺ * minkowski_distance + β} * 𝛄 + s
            uint64_t receiver_to_sender_g_alpha_minkowski_beta_gamma_secret = g_alpha_minkowski_beta_gamma_secret;
            vector<uint64_t> receiver_to_sender_group_vector_square_threshold_using_hash = group_vector_square_threshold_using_hash;

            // #13. Sender 는 미리 받은 g^𝛄 에 대해 g^β𝛄 을 계산한 후, inverse g^β𝛄 계산
            uint64_t g_beta_gamma = group_arithmetic(receiver_to_sender_g_gamma, beta);   
            uint64_t g_beta_gamma_inverse = mod_inv(g_beta_gamma);

            // #14. Sender 는 receiver_to_sender_g_alpha_minkowski_beta_gamma_secret * g^β𝛄 ^-1 에 대해 Fuzzy Matching 수행
            uint64_t fuzzy_matching_result = mod_mul(receiver_to_sender_g_alpha_minkowski_beta_gamma_secret, g_beta_gamma_inverse);

            bool found_match = false;
            for (auto& element : receiver_to_sender_group_vector_square_threshold_using_hash) {
                if (fuzzy_matching_result == element) {
                    cout << "Fuzzy Matching 성공! " << sender_cnt << " -> " << receiver_cnt << " 일치하는 값: " << element << endl;
                    found_match = true;
                    break;
                }
            }

            if (!found_match) {
                cout << "Fuzzy Matching 실패! " << sender_cnt << " -> " << receiver_cnt << " 일치하는 값이 없습니다." << endl;
            }
        }
    }
    
    
    // 시간 측정 종료 및 결과 출력
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = end_time - start_time;
    cout << "실행 시간: " << elapsed_time.count() << " 초" << endl;

    return 0;
}