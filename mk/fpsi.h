#pragma once

#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <random>
#include <cstdint>

// seed 생성기
static std::random_device rd;
// 난수발생기
static std::mt19937_64 gen(rd());

// 128‑bit uniform random helper
// NOTE: 2025‑07‑25  — switched mod_mul128 to true 128×128→128 reduction
//                      and introduced to_uint_exponent for correct
//                      handling of negative exponents.
// NOTE: mapped to [0, p-1]   (additive group allows zero)
inline uint64_t rand_u64()
{
    return gen();
}

// 수정: 64비트 상수 정의
constexpr uint64_t Q = 17992246208926924127ULL; // 64비트 소수 모듈러스
constexpr uint64_t P = 8996123104463462063ULL;  // 64비트 서브그룹 차수
constexpr uint64_t PRIMITIVE_ROOT = 5;          // Q의 원시근
constexpr uint64_t ORDER = 2;                    // (Q-1)/P
constexpr uint64_t G = PRIMITIVE_ROOT * PRIMITIVE_ROOT % Q; // 서브그룹 생성원 g

/**
 * Converts signed x to [0, p-1] for additive group, zeros allowed
 */
// 수정: signed int64 -> uint64 변환

// 추가: 64비트 범위 랜덤 유틸
inline uint64_t random_Zp(uint64_t p = Q)
{
    // (-q/2, q/2) 범위를 출력하도록 변경
    return (rand_u64() % p) - (p / 2);
}

/**
 * Converts a signed integer x into its modulo p representative in [0, p-1].
 */

// 수정: 64비트 모듈러 곱셈
inline uint64_t mod_mul(uint64_t a, uint64_t b)
{
    return (static_cast<__uint128_t>(a) * b) % Q;
}

// 수정: 64비트 모듈러 거듭제곱
inline uint64_t mod_pow(uint64_t base, uint64_t exp)
{
    uint64_t res = 1;
    base %= Q;
    while (exp)
    {
        if (exp & 1)
            res = (res * static_cast<__uint128_t>(base)) % Q;
        base = (static_cast<__uint128_t>(base) * base) % Q;
        exp >>= 1;
    }
    return res;
}

/**
 * Multiplicative subgroup ⟨G128⟩ of Z_Q128*  (order P128).
 * Returns g^k mod Q128 with 1 ≤ g,k ≤ P128−1.
 */
// 수정: 64비트 서브그룹 연산
inline uint64_t group_arithmetic(uint64_t g, uint64_t k)
{
    return mod_pow(g, k); // g^k mod Q
}

// 수정: 64비트 생성원 반환
inline uint64_t generator()
{
    return G;
}


// 수정: 64비트 모듈러 역원 (Extended GCD)
inline uint64_t mod_inv(uint64_t a) {
    // Extended Euclidean Algorithm to find x, y such that ax + Qy = gcd(a, Q)
    __int128 t = 0, new_t = 1;
    uint64_t r = Q, new_r = a;
    while (new_r != 0) {
        uint64_t q = r / new_r;
        __int128 tmp_t = t - (__int128)q * new_t;
        t = new_t;
        new_t = tmp_t;
        uint64_t tmp_r = r - q * new_r;
        r = new_r;
        new_r = tmp_r;
    }
    // If r > 1, a is not invertible
    if (r != 1) {
        return 0; // no inverse
    }
    // Make sure result is positive
    if (t < 0) t += Q;
    return static_cast<uint64_t>(t);
}