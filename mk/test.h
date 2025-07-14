
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

inline void print_plain_rns_coeff(
    const seal::Plaintext& in, const seal::SEALContext& context, size_t length = 5)
{
    auto context_data_ptr = context.get_context_data(in.parms_id());
    auto& parms = context_data_ptr->parms();
    auto& coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    std::size_t coeff_count = parms.poly_modulus_degree();
    auto ntt_tables = context_data_ptr->small_ntt_tables();

    seal::Plaintext in_copy = in;

    if (in_copy.is_ntt_form())
    {
        for (std::size_t i = 0; i < coeff_modulus_size; i++)
        {
            seal::util::inverse_ntt_negacyclic_harvey(in_copy.data(i * coeff_count), ntt_tables[i]);
        }
    }

    const seal::Plaintext::pt_coeff_type* ptr = in_copy.data();

    std::cout << "/" << std::endl;
    std::cout << "| Plaintext RNS coeff :" << std::endl;
    for (size_t j = 0; j < coeff_modulus_size; j++)
    {
        uint64_t modulus = coeff_modulus[j].value();
        size_t poly_modulus_degree = parms.poly_modulus_degree();
        for (; poly_modulus_degree--; ptr++)
        {
            if (poly_modulus_degree < length)
            //if (j == 0)
            {
                std::cout << *ptr << ' ';
            }
        }
        std::cout << "mod " << modulus << std::endl;
    }
    std::cout << "\\" << std::endl;
}

inline void print_cipher_rns_coeff(
    const seal::Ciphertext& in, const seal::SEALContext& context, const seal::Evaluator &evaluator)
{
    auto context_data_ptr = context.get_context_data(in.parms_id());
    const auto& coeff_modulus = context_data_ptr->parms().coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();

    seal::Ciphertext in_copy = in;

    if (in_copy.is_ntt_form())
    {
        evaluator.transform_from_ntt_inplace(in_copy);
    }

    const seal::Ciphertext::ct_coeff_type* ptr = in_copy.data();
    auto size = in_copy.size();

    std::cout << "/" << std::endl;
    std::cout << "| Ciphertext RNS coeff :" << std::endl;
    for (size_t i = 0; i < size; i++)
    {
        std::cout << "c_" << i << std::endl;
        for (size_t j = 0; j < coeff_modulus_size; j++)
        {
            uint64_t modulus = coeff_modulus[j].value();
            auto poly_modulus_degree = in_copy.poly_modulus_degree();
            for (; poly_modulus_degree--; ptr++)
            {
                if (poly_modulus_degree < 3)
                //if (j == 0)
                {
                    std::cout << *ptr << ' ';
                }
            }
            std::cout << "mod " << modulus << std::endl;
        }
    }
    std::cout << "\\" << std::endl;
}