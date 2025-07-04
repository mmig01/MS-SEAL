#include "seal/bootstrapper.h"
#include <iostream>
#include <chrono>

using namespace std;
using namespace seal::util;
using namespace std::chrono;

namespace seal
{
    CKKSBootstrapper::CKKSBootstrapper(const SEALContext &context) : context_(context)
    {
        // Verify parameters.
        auto &first_parms = context_.first_context_data()->parms();
        if (!context_.using_bootstrapping())
        {
            throw logic_error("bootstrapping is not supported by the context");
        }
        if (first_parms.scheme() != scheme_type::ckks)
        {
            throw invalid_argument("unsupported scheme");
        }

        // Extract encryption parameters.
        uint64_t n = first_parms.poly_modulus_degree();
        uint64_t m = n << 1;
        uint64_t slot_count = n >> 1;
        uint64_t bs = 1ULL << static_cast<uint64_t>(log2(sqrt(slot_count)));
        uint64_t gs = slot_count / bs;

        // Create m-th complex root generator
        auto m_th_complex_root = [&](uint64_t i) {
            return polar<double_t>(1.0, 2.0 * PI_ * static_cast<double_t>(i) / static_cast<double_t>(m));
        };

        // Create U matrix.
        vector<vector<complex<double_t>>> U0(slot_count, vector<complex<double_t>>(slot_count));
        vector<vector<complex<double_t>>> U1(slot_count, vector<complex<double_t>>(slot_count));

        uint64_t gen = 3;
        uint64_t gap = 1;
        uint64_t exp = 0;
        for (size_t i = 0; i < slot_count; i++)
        {
            exp = 0;
            for (size_t j = 0; j < slot_count; j++)
            {
                U0[i][j] = m_th_complex_root(exp);
                exp = (exp + gap) % m;
            }
            for (size_t j = 0; j < slot_count; j++)
            {
                U1[i][j] = m_th_complex_root(exp);
                exp = (exp + gap) % m;
            }
            gap = (gap * gen) % m;
        }

        // Create U diag matrix.
        U0_diag_.resize(slot_count);
        U1_diag_.resize(slot_count);
        U0_t_diag_.resize(slot_count);
        U1_t_diag_.resize(slot_count);
        U0_t_c_diag_.resize(slot_count);
        U1_t_c_diag_.resize(slot_count);

        for (size_t j = 0; j < gs; j++)
        {
            for (size_t i = 0; i < bs; i++)
            {
                size_t k = (j * bs) + i;
                U0_diag_[k].resize(slot_count);
                U1_diag_[k].resize(slot_count);
                U0_t_diag_[k].resize(slot_count);
                U1_t_diag_[k].resize(slot_count);
                U0_t_c_diag_[k].resize(slot_count);
                U1_t_c_diag_[k].resize(slot_count);

                size_t ii = 0;
                size_t jj = k;
                size_t bs_rot = bs * j;
                for (size_t c = 0; c < slot_count; c++)
                {
                    size_t coeff_idx = (c + bs_rot) % slot_count;
                    U0_diag_[k][coeff_idx] = U0[ii][jj];
                    U1_diag_[k][coeff_idx] = U1[ii][jj];
                    U0_t_diag_[k][coeff_idx] = U0[jj][ii];
                    U1_t_diag_[k][coeff_idx] = U1[jj][ii];
                    U0_t_c_diag_[k][coeff_idx] = conj(U0[jj][ii]);
                    U1_t_c_diag_[k][coeff_idx] = conj(U1[jj][ii]);
                    ii++;
                    jj = (jj + 1) % slot_count;
                }
            }
        }
    }

    size_t CKKSBootstrapper::get_bootstrap_depth(int delta_bit, size_t l, size_t d_0, size_t r)
    {
        if (d_0 < 1)
        {
            throw invalid_argument("d_0 must be at least 1.");
        }
            
        /*                    Step                                   Depth Consumption
            ─────────────────────────────────────────
            1) Coeff-to-Slot (CTS)                                         2
            2) Eval mod q_0
                ┌─ Multiply constant (2πi / 2^r)                      1
                ├─ Divide by q_l                                           l + 1
                ├─ Taylor expansion (degree d₀)          ⌊log₂(d₀)⌋ + 2
                ├─ Exponentiation (·)^{2^r}                            r
                └─ Multiply constant q_l / (2π)                     l + 1
            3) Slot-to-Coeff (STC)                                         2
            ─────────────────────────────────────────
        */

        size_t taylor_cnt = static_cast<size_t>(log2(d_0)) + 2;

        return (2 + 1 + taylor_cnt + r + (l + 1) + 2) * (delta_bit > 60 ? 2 : 1) + (l + 1);
    }

    vector<int> CKKSBootstrapper::create_coeff_modulus(
        vector<int> coeff_modulus, int scale_bit, int delta_bit, size_t l, size_t d_0, size_t r)
    {
        // Verify parameters.
        if (coeff_modulus.size() < 2)
        {
            throw invalid_argument("coeff_modulus must contain at least two primes.");
        }
        if (delta_bit < 0 || delta_bit > 120)
        {
            throw invalid_argument("delta_bit must be in the range [0, 120].");
        }
        if (coeff_modulus.size() < l + 1)
        {
            throw invalid_argument("coeff_modulus must contain at least (l + 1) primes to support bootstrapping.");
        }
        if (d_0 < 1)
        {
            throw invalid_argument("d_0 must be at least 1.");
        }

        // Extend coefficient modulus.
        vector<int> extend_coeff_modulus(coeff_modulus.begin(), coeff_modulus.end() - 1);

        // Add a modulus' bit.
        auto add_bit = [&](int bit) {
            if (bit <= 60)
            {
                extend_coeff_modulus.push_back(bit);
            }
            else if (bit < 80)
            {
                int base_bit = 40;
                extend_coeff_modulus.push_back(base_bit);
                extend_coeff_modulus.push_back(bit - base_bit);
            }
            else if (bit < 100)
            {
                int base_bit = 50;
                extend_coeff_modulus.push_back(base_bit);
                extend_coeff_modulus.push_back(bit - base_bit);
            }
            else if (bit <= 120)
            {
                int base_bit = 60;
                extend_coeff_modulus.push_back(base_bit);
                extend_coeff_modulus.push_back(bit - base_bit);
            }
            else
            {
                throw invalid_argument("Bit-length for modulus primes must not exceed 120.");
            }
        };

        // STC.
        // Depth = 2.
        for (size_t i = 0; i < 2; i++)
        {
            add_bit(delta_bit);
        }

        // (ct_0, ct_1) = { q_l / (2 * PI) } * (ct_0.imag, ct_1.imag).
        // Depth = l + 1.
        for (size_t i = 0; i <= l; i++)
        {
            add_bit(delta_bit);
        }

        // (P_r_0, P_r_1) = (P_0_0, P_0_1)^{2^r}.
        // Depth = r.
        for (size_t i = 0; i < r; i++)
        {
            add_bit(delta_bit);
        }

        // (P_0_0, P_0_1) = Σ{(1 / k!) * (term_1_0, term_1_1)^k}. Where k = {0, 1, ... , d_0}.
        // Depth = floor(log2(r)) + 2.
        size_t taylor_cnt = static_cast<size_t>(log2(d_0)) + 2;
        for (size_t i = 0; i < taylor_cnt; i++)
        {
            add_bit(delta_bit);
        }

        // (term_1_0, term_1_1) = (term_1_0, term_1_1) / q_l.
        // Depth = l + 1.
        for (size_t i = 0; i <= l; i++)
        {
            add_bit(coeff_modulus[l - i]);
        }

        // (term_1_0, term_1_1) = {(2 * PI * i) / (2^r)} * (ct_0, ct_1).
        // Depth = 1.
        add_bit(delta_bit);
        
        // CTS.
        // Depth = 2.
        for (size_t i = 0; i < 2; i++)
        {
            add_bit(delta_bit);
        }

        // Add p.
        extend_coeff_modulus.push_back(coeff_modulus.back());

        return extend_coeff_modulus;
    };

    void CKKSBootstrapper::bootstrapping(
        const Ciphertext &encrypted, const CKKSEncoder &encoder, const Encryptor &encryptor, const Evaluator &evaluator,
        const RelinKeys &relin_keys, const GaloisKeys &galois_keys, int scale_bit, int delta_bit, size_t l, size_t d_0,
        size_t r, Ciphertext &destination, bool print_progress) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.using_bootstrapping())
        {
            throw logic_error("bootstrapping is not supported by the context");
        }
        if (context_.first_context_data()->parms().bootstrapping_depth() != get_bootstrap_depth(delta_bit, l, d_0, r))
        {
            throw logic_error("The context's bootstrapping_depth does not match the depth implied by (l, d_0, r).");
        }
        if (scale_bit < 0 || scale_bit > 120)
        {
            throw invalid_argument("scale_bit must be in the range [0, 120].");
        }
        if (delta_bit < 0 || delta_bit > 120)
        {
            throw invalid_argument("delta_bit must be in the range [0, 120].");
        }
        if (d_0 < 1)
        {
            throw invalid_argument("d_0 must be at least 1.");
        }
        
        // Start timer
        auto start = high_resolution_clock::now();
        if (print_progress)
        {
            std::cout << "┌──" << std::endl;
            std::cout << "| Progress :" << std::endl;
        }

        // Copy
        Ciphertext encrypted_copy = encrypted;
        Ciphertext ct_0;
        Ciphertext ct_1;

        // Modulus down to q_l.
        while (encrypted_copy.coeff_modulus_size() > l + 1)
        {
            evaluator.mod_reduce_to_next_inplace(encrypted_copy);
        }

        // Modulus up to Q_0.
        evaluator.mod_raise_to_first_inplace(encrypted_copy);

        // CTS.
        coeff_to_slot(
            encrypted_copy, encoder, evaluator, scale_bit, delta_bit, galois_keys, ct_0, ct_1, print_progress);

        // Mod q_l.
        approximate_mod_q_l(
            ct_0, ct_1, encoder, encryptor, evaluator, relin_keys, galois_keys, delta_bit, l, d_0, r, ct_0, ct_1,
            print_progress);

        // STC.
        slot_to_coeff(ct_0, ct_1, encoder, evaluator, scale_bit, delta_bit, galois_keys, destination, print_progress);
        
        // Stop timer and print elapsed time
        auto end = high_resolution_clock::now(); 
        if (print_progress)
        {
            auto duration = duration_cast<milliseconds>(end - start);
            cout << "|   Execution time: " << duration.count() << " ms\n";
            std::cout << "└──" << std::endl << std::endl;
        }
    }

    void CKKSBootstrapper::coeff_to_slot(
        const Ciphertext &encrypted, const CKKSEncoder &encoder, const Evaluator &evaluator, int scale_bit,
        int delta_bit, const GaloisKeys &galois_keys, Ciphertext &destination1, Ciphertext &destination2,
        bool print_progress) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.using_bootstrapping())
        {
            throw logic_error("bootstrapping is not supported by the context");
        }
        if (scale_bit < 0 || scale_bit > 120)
        {
            throw invalid_argument("scale_bit must be in the range [0, 120].");
        }
        if (delta_bit < 0 || delta_bit > 120)
        {
            throw invalid_argument("delta_bit must be in the range [0, 120].");
        }

        // Extract encryption parameters.
        auto &first_parms = context_.first_context_data()->parms();
        const auto &coeff_modulus = first_parms.coeff_modulus();
        uint64_t n = first_parms.poly_modulus_degree();
        uint64_t slot_count = n >> 1;
        uint64_t bs = 1ULL << static_cast<uint64_t>(log2(sqrt(slot_count)));
        uint64_t gs = slot_count / bs;
        double_t scale = pow(2, scale_bit);
        double_t delta = pow(2, delta_bit);

        // CTS: Enc(z) -> (Enc(z_0), Enc(z_1)).
        // Where z is message vector of n/2 dimension, concat(z_0, z_1) is message coefficient of n degree.
        // Enc(z_0) = Enc(1/n * (conj(U0^t) * z + U0^t * conj(z))).
        // Enc(z_1) = Enc(1/n * (conj(U1^t) * z + U1^t * conj(z))).
        // Depth = 1.
        Plaintext U0_t_c_diag_i;
        Plaintext U1_t_c_diag_i;
        Plaintext U0_t_diag_i;
        Plaintext U1_t_diag_i;
        Plaintext inv_n;
        vector<Ciphertext> z_rot;
        vector<Ciphertext> z_c_rot;
        Ciphertext z_0;
        Ciphertext z_1;

        // Temp var.
        vector<complex<double_t>> tmp_vt;
        Plaintext tmp_pt;
        Ciphertext tmp_ct_0;
        Ciphertext tmp_ct_1;

        // Rotate ciphertext.
        z_rot.resize(bs);
        z_c_rot.resize(bs);
        z_rot[0] = encrypted;
        evaluator.complex_conjugate(z_rot[0], galois_keys, z_c_rot[0]);
        for (size_t i = 1; i < bs; i++)
        {
            evaluator.rotate_vector(z_rot[0], static_cast<int>(i), galois_keys, z_rot[i]);
            evaluator.rotate_vector(z_c_rot[0], static_cast<int>(i), galois_keys, z_c_rot[i]);
        }

        // Linear transformation.
        size_t process_cnt_cts = 0;
        for (size_t j = 0; j < gs; j++)
        {
            Ciphertext z_0_bs;
            Ciphertext z_1_bs;

            for (size_t i = 0; i < bs; i++)
            {
                size_t k = (j * bs) + i;
                if (print_progress)
                {
                    print_progress_percent("Coeff-to-Slot", k + 1, slot_count);
                }
                encoder.encode(U0_t_diag_[k], z_rot[i].parms_id(), delta, U0_t_diag_i);
                encoder.encode(U1_t_diag_[k], z_rot[i].parms_id(), delta, U1_t_diag_i);
                encoder.encode(U0_t_c_diag_[k], z_rot[i].parms_id(), delta, U0_t_c_diag_i);
                encoder.encode(U1_t_c_diag_[k], z_rot[i].parms_id(), delta, U1_t_c_diag_i);

                // z_0 += conj(U0^t) * z.
                // z_1 += conj(U1^t) * z.
                if (i == 0)
                {
                    evaluator.multiply_plain(z_rot[i], U0_t_c_diag_i, z_0_bs);
                    evaluator.multiply_plain(z_rot[i], U1_t_c_diag_i, z_1_bs);
                }
                else
                {
                    evaluator.multiply_plain(z_rot[i], U0_t_c_diag_i, tmp_ct_0);
                    evaluator.multiply_plain(z_rot[i], U1_t_c_diag_i, tmp_ct_1);
                    evaluator.add_inplace(z_0_bs, tmp_ct_0);
                    evaluator.add_inplace(z_1_bs, tmp_ct_1);
                }

                // z_0 += U0^t * conj(z).
                // z_1 += U1^t * conj(z).
                evaluator.multiply_plain(z_c_rot[i], U0_t_diag_i, tmp_ct_0);
                evaluator.multiply_plain(z_c_rot[i], U1_t_diag_i, tmp_ct_1);
                evaluator.add_inplace(z_0_bs, tmp_ct_0);
                evaluator.add_inplace(z_1_bs, tmp_ct_1);
            }

            size_t gs_rot = bs * j;
            if (j == 0)
            {
                evaluator.rotate_vector(z_0_bs, static_cast<int>(gs_rot), galois_keys, z_0);
                evaluator.rotate_vector(z_1_bs, static_cast<int>(gs_rot), galois_keys, z_1);
            }
            else
            {
                evaluator.rotate_vector_inplace(z_0_bs, static_cast<int>(gs_rot), galois_keys);
                evaluator.rotate_vector_inplace(z_1_bs, static_cast<int>(gs_rot), galois_keys);
                evaluator.add_inplace(z_0, z_0_bs);
                evaluator.add_inplace(z_1, z_1_bs);
            }
        }

        dynamic_rescale_inplace(z_0, evaluator, delta_bit);
        dynamic_rescale_inplace(z_1, evaluator, delta_bit);
        

        tmp_vt.assign(
            slot_count,
            (delta / static_cast<double_t>(n)) * dynamic_correction_factor(z_0, scale, delta, delta_bit, 0));
        encoder.encode(tmp_vt, z_0.parms_id(), delta, tmp_pt);
        evaluator.multiply_plain_inplace(z_0, tmp_pt);
        evaluator.multiply_plain_inplace(z_1, tmp_pt);
        dynamic_rescale_inplace(z_0, evaluator, delta_bit);
        dynamic_rescale_inplace(z_1, evaluator, delta_bit);

        z_0.scale() = delta;
        z_1.scale() = delta;

        // Copy result to destination.
        destination1 = z_0;
        destination2 = z_1;
    }

    void CKKSBootstrapper::slot_to_coeff(
        const Ciphertext &encrypted1, const Ciphertext &encrypted2, const CKKSEncoder &encoder,
        const Evaluator &evaluator, int scale_bit, int delta_bit, const GaloisKeys &galois_keys,
        Ciphertext &destination, bool print_progress) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (!context_.using_bootstrapping())
        {
            throw logic_error("bootstrapping is not supported by the context");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.scale() != encrypted2.scale())
        {
            throw invalid_argument("encrypted1 and encrypted2 scale mismatch");
        }
        if (scale_bit < 0 || scale_bit > 120)
        {
            throw invalid_argument("scale_bit must be in the range [0, 120].");
        }
        if (delta_bit < 0 || delta_bit > 120)
        {
            throw invalid_argument("delta_bit must be in the range [0, 120].");
        }

        // Extract encryption parameters.
        auto &first_parms = context_.first_context_data()->parms();
        const auto &coeff_modulus = first_parms.coeff_modulus();
        uint64_t n = first_parms.poly_modulus_degree();
        uint64_t slot_count = n >> 1;
        uint64_t bs = 1ULL << static_cast<uint64_t>(log2(sqrt(slot_count)));
        uint64_t gs = slot_count / bs;
        double_t scale = pow(2, scale_bit);
        double_t delta = pow(2, delta_bit);

        // STC: (Enc(z_0), Enc(z_1)) -> Enc(z).
        // Where z is message vector of n/2 dimension, concat(z_0, z_1) is message coefficient of n degree.
        // Enc(z) = Enc(U0 * z_0 + U1 * z_1).
        // Depth = 1.
        Plaintext U0_diag_i;
        Plaintext U1_diag_i;
        Ciphertext z;
        vector<Ciphertext> z_0_rot;
        vector<Ciphertext> z_1_rot;

        // Temp var.
        vector<complex<double_t>> tmp_vt;
        Plaintext tmp_pt;
        Ciphertext tmp_ct;

        // Rotate ciphertext.
        z_0_rot.resize(bs);
        z_1_rot.resize(bs);
        z_0_rot[0] = encrypted1;
        z_1_rot[0] = encrypted2;
        for (size_t i = 1; i < bs; i++)
        {
            evaluator.rotate_vector(z_0_rot[0], static_cast<int>(i), galois_keys, z_0_rot[i]);
            evaluator.rotate_vector(z_1_rot[0], static_cast<int>(i), galois_keys, z_1_rot[i]);
        }

        // Corrected scale
        double_t corrected_scale = delta;
        corrected_scale *= dynamic_correction_factor(encrypted1, delta, delta, delta_bit, 0);
        corrected_scale *= dynamic_correction_factor(encrypted1, delta, delta, delta_bit, 1);

        // Linear transformation.
        for (size_t j = 0; j < gs; j++)
        {
            Ciphertext z_bs;

            for (size_t i = 0; i < bs; i++)
            {
                size_t k = (j * bs) + i;
                if (print_progress)
                {
                    print_progress_percent("Slot-to-Coeff", k + 1, slot_count);
                }
                encoder.encode(U0_diag_[k], z_0_rot[i].parms_id(), corrected_scale, U0_diag_i);
                encoder.encode(U1_diag_[k], z_1_rot[i].parms_id(), corrected_scale, U1_diag_i);

                // z += U0 * z_0.
                if (i == 0)
                {
                    evaluator.multiply_plain(z_0_rot[i], U0_diag_i, z_bs);
                }
                else
                {
                    evaluator.multiply_plain(z_0_rot[i], U0_diag_i, tmp_ct);
                    evaluator.add_inplace(z_bs, tmp_ct);
                }

                // z += U1 * z_1.
                evaluator.multiply_plain(z_1_rot[i], U1_diag_i, tmp_ct);
                evaluator.add_inplace(z_bs, tmp_ct);
            }

            size_t gs_rot = bs * j;
            if (j == 0)
            {
                evaluator.rotate_vector(z_bs, static_cast<int>(gs_rot), galois_keys, z);
            }
            else
            {
                evaluator.rotate_vector_inplace(z_bs, static_cast<int>(gs_rot), galois_keys);
                evaluator.add_inplace(z, z_bs);
            }
        }

        // Rescale
        dynamic_rescale_inplace(z, evaluator, delta_bit);
        z.scale() = delta;

        // Scaling
        dynamic_rescale_inplace(z, evaluator, delta_bit);
        z.scale() = scale;

        // Copy result to destination.
        destination = z;
    }

    void CKKSBootstrapper::approximate_mod_q_l(
        const Ciphertext &encrypted1, const Ciphertext &encrypted2, const CKKSEncoder &encoder,
        const Encryptor &encryptor, const Evaluator &evaluator, const RelinKeys &relin_keys,
        const GaloisKeys &galois_keys, int delta_bit, size_t l, size_t d_0, size_t r, Ciphertext &destination1,
        Ciphertext &destination2, bool print_progress) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (!context_.using_bootstrapping())
        {
            throw logic_error("bootstrapping is not supported by the context");
        }
        if (context_.first_context_data()->parms().bootstrapping_depth() != get_bootstrap_depth(delta_bit, l, d_0, r))
        {
            throw logic_error("The context's bootstrapping_depth does not match the depth implied by (l, d_0, r).");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.scale() != encrypted2.scale())
        {
            throw invalid_argument("encrypted1 and encrypted2 scale mismatch");
        }
        if (delta_bit < 0 || delta_bit > 120)
        {
            throw invalid_argument("delta_bit must be in the range [0, 120].");
        }
        if (d_0 < 1)
        {
            throw invalid_argument("d_0 must be at least 1.");
        }

        // Extract encryption parameters.
        auto &first_parms = context_.first_context_data()->parms();
        const auto &coeff_modulus = first_parms.coeff_modulus();
        uint64_t n = first_parms.poly_modulus_degree();
        uint64_t slot_count = n >> 1;
        double_t delta = pow(2, delta_bit);

        // Modular reduction: (Enc(ct_0), Enc(ct_1)) -> (Enc(Dec(ct_0) mod q_l), Enc(Dec(ct_1) mod q_l))
        Ciphertext ct_0 = encrypted1;
        Ciphertext ct_1 = encrypted2;

        // (term_1_0, term_1_1) = {(2 * PI * i) / (q_l * 2^r)} * (ct_0, ct_1).
        // Depth = (l + 1) + 1.
        if (print_progress)
        {
            print_progress_percent("Eval mod q_0", 1, 4);
        }
        Ciphertext term_1_0 = ct_0;
        Ciphertext term_1_1 = ct_1;
        [&]() {
            // Temp var.
            vector<complex<double_t>> tmp_vt;
            Plaintext tmp_pt;

            // (term_1_0, term_1_1) = {(2 * PI * i) / (2^r)} * (ct_0, ct_1).
            complex<double_t> angle(0.0, (2.0 * PI_) / static_cast<double_t>(1ULL << r));
            size_t last_modulus_index = term_1_0.coeff_modulus_size() - (delta_bit <= 60 ? 2ULL : 3ULL);
            for (size_t i = 0; i <= l; i++)
            {
                uint64_t q_i_dot = coeff_modulus[last_modulus_index - i].value();
                uint64_t q_i = coeff_modulus[i].value();
                angle *= static_cast<double_t>(q_i_dot) / static_cast<double_t>(q_i);
            };
            tmp_vt.assign(slot_count, angle * dynamic_correction_factor(term_1_0, delta, delta, delta_bit, 0));
            encoder.encode(tmp_vt, term_1_0.parms_id(), delta, tmp_pt);
            evaluator.multiply_plain_inplace(term_1_0, tmp_pt);
            evaluator.multiply_plain_inplace(term_1_1, tmp_pt);
            dynamic_rescale_inplace(term_1_0, evaluator, delta_bit);
            dynamic_rescale_inplace(term_1_1, evaluator, delta_bit);

            term_1_0.scale() = delta;
            term_1_1.scale() = delta;

            // (term_1_0, term_1_1) = (term_1_0, term_1_1) / q_l.
            for (size_t i = 0; i <= l; i++)
            {
                uint64_t last_modulus = coeff_modulus[term_1_0.coeff_modulus_size() - 1ULL - i].value();
                term_1_0.scale() = static_cast<double_t>(last_modulus);
                term_1_1.scale() = static_cast<double_t>(last_modulus);
                dynamic_rescale_inplace(term_1_0, evaluator, 60);
                dynamic_rescale_inplace(term_1_1, evaluator, 60);
            }

            term_1_0.scale() = delta;
            term_1_1.scale() = delta;
        }();

        // (P_0_0, P_0_1) = Σ{(1 / k!) * (term_1_0, term_1_1)^k}. Where k = {0, 1, ... , d_0}.
        // Depth = floor(log2(d_0)) + 2.
        if (print_progress)
        {
            print_progress_percent("Eval mod q_0", 2, 4);
        }
        Ciphertext P_r_0;
        Ciphertext P_r_1;
        [&]() {
            // Temp var.
            vector<complex<double_t>> tmp_vt;
            Plaintext tmp_pt;
            Ciphertext tmp_ct_0;
            Ciphertext tmp_ct_1;

            vector<Ciphertext> terms_0(d_0 + 1);
            vector<Ciphertext> terms_1(d_0 + 1);

            terms_0[1] = term_1_0;
            terms_1[1] = term_1_1;

            tmp_vt.assign(slot_count, 1.0);
            encoder.encode(tmp_vt, terms_0[1].parms_id(), delta, tmp_pt);
            evaluator.add_plain(terms_0[1], tmp_pt, P_r_0);
            evaluator.add_plain(terms_1[1], tmp_pt, P_r_1);

            uint64_t po2 = 1ULL;
            double_t inv_fact = 1.0;
            for (size_t i = 2; i <= d_0; i++)
            {
                if ((po2 << 1ULL) == i)
                {
                    evaluator.square(terms_0[po2], terms_0[i]);
                    evaluator.square(terms_1[po2], terms_1[i]);
                    evaluator.relinearize_inplace(terms_0[i], relin_keys);
                    evaluator.relinearize_inplace(terms_1[i], relin_keys);
                    dynamic_rescale_inplace(terms_0[i], evaluator, delta_bit);
                    dynamic_rescale_inplace(terms_1[i], evaluator, delta_bit);
                    po2 = i;
                }
                else
                {
                    tmp_ct_0 = terms_0[i - po2];
                    tmp_ct_1 = terms_1[i - po2];
                    evaluator.mod_reduce_to_inplace(tmp_ct_0, terms_0[po2].parms_id());
                    evaluator.mod_reduce_to_inplace(tmp_ct_1, terms_1[po2].parms_id());
                    evaluator.multiply(terms_0[po2], tmp_ct_0, terms_0[i]);
                    evaluator.multiply(terms_1[po2], tmp_ct_1, terms_1[i]);
                    evaluator.relinearize_inplace(terms_0[i], relin_keys);
                    evaluator.relinearize_inplace(terms_1[i], relin_keys);
                    dynamic_rescale_inplace(terms_0[i], evaluator, delta_bit);
                    dynamic_rescale_inplace(terms_1[i], evaluator, delta_bit);
                }

                inv_fact /= static_cast<double_t>(i);
                tmp_vt.assign(slot_count, inv_fact * dynamic_correction_factor(terms_0[i], delta, delta, delta_bit, 0));
                encoder.encode(tmp_vt, terms_0[i].parms_id(), delta, tmp_pt);
                evaluator.multiply_plain(terms_0[i], tmp_pt, tmp_ct_0);
                evaluator.multiply_plain(terms_1[i], tmp_pt, tmp_ct_1);
                dynamic_rescale_inplace(tmp_ct_0, evaluator, delta_bit);
                dynamic_rescale_inplace(tmp_ct_1, evaluator, delta_bit);
                tmp_ct_0.scale() = delta;
                tmp_ct_1.scale() = delta;

                evaluator.mod_reduce_to_inplace(P_r_0, tmp_ct_0.parms_id());
                evaluator.mod_reduce_to_inplace(P_r_1, tmp_ct_1.parms_id());
                evaluator.add_inplace(P_r_0, tmp_ct_0);
                evaluator.add_inplace(P_r_1, tmp_ct_1);
            }
        }();

        // (P_r_0, P_r_1) = (P_0_0, P_0_1)^{2^r}.
        // Depth = r.
        if (print_progress)
        {
            print_progress_percent("Eval mod q_0", 3, 4);
        }
        [&]() {
            for (size_t i = 0; i < r; i++)
            {
                evaluator.square_inplace(P_r_0);
                evaluator.square_inplace(P_r_1);
                evaluator.relinearize_inplace(P_r_0, relin_keys);
                evaluator.relinearize_inplace(P_r_1, relin_keys);
                dynamic_rescale_inplace(P_r_0, evaluator, delta_bit);
                dynamic_rescale_inplace(P_r_1, evaluator, delta_bit);
            }
        }();

        // (ct_0, ct_1) = {q_l / (2 * PI)} * (ct_0.imag, ct_1.imag).
        // Depth = l + 1.
        if (print_progress)
        {
            print_progress_percent("Eval mod q_0", 4, 4);
        }
        [&]() {
            // Temp var.
            vector<complex<double_t>> tmp_vt;
            Plaintext tmp_pt;
            Ciphertext tmp_ct_0;
            Ciphertext tmp_ct_1;

            // (ct_0, ct_1) = (P_r_0, P_r_1) - conj(P_r_0, P_r_1).
            evaluator.complex_conjugate(P_r_0, galois_keys, tmp_ct_0);
            evaluator.complex_conjugate(P_r_1, galois_keys, tmp_ct_1);
            evaluator.sub(tmp_ct_0, P_r_0, ct_0);
            evaluator.sub(tmp_ct_1, P_r_1, ct_1);

            // (ct_0, ct_1) = (q_0 * i) / (4 * PI) * (ct_0, ct_1).
            complex<double_t> rate(0.0, static_cast<double_t>(coeff_modulus[0].value()) / (4.0 * PI_));
            tmp_vt.assign(slot_count, rate * dynamic_correction_factor(ct_0, delta, delta, delta_bit, 0));
            encoder.encode(tmp_vt, ct_0.parms_id(), delta, tmp_pt);
            evaluator.multiply_plain_inplace(ct_0, tmp_pt);
            evaluator.multiply_plain_inplace(ct_1, tmp_pt);
            dynamic_rescale_inplace(ct_0, evaluator, delta_bit);
            dynamic_rescale_inplace(ct_1, evaluator, delta_bit);
            ct_0.scale() = delta;
            ct_1.scale() = delta;

            // (ct_0, ct_1) = (q_l / q_0)  * (ct_0, ct_1).
            for (size_t i = 1; i <= l; i++)
            {
                double_t q_i = static_cast<double_t>(coeff_modulus[i].value());
                tmp_vt.assign(slot_count, q_i * dynamic_correction_factor(ct_0, delta, delta, delta_bit, 0));
                encoder.encode(tmp_vt, ct_0.parms_id(), delta, tmp_pt);
                evaluator.multiply_plain_inplace(ct_0, tmp_pt);
                evaluator.multiply_plain_inplace(ct_1, tmp_pt);
                dynamic_rescale_inplace(ct_0, evaluator, delta_bit);
                dynamic_rescale_inplace(ct_1, evaluator, delta_bit);
                ct_0.scale() = delta;
                ct_1.scale() = delta;
            }
        }();

        // Copy result to destination.
        destination1 = ct_0;
        destination2 = ct_1;
    }

    double_t CKKSBootstrapper::dynamic_correction_factor(
        const Ciphertext &encrypted, double_t curr_scale, double_t target_scale, int rescale_bit,
        size_t nth_rescale) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.using_bootstrapping())
        {
            throw logic_error("bootstrapping is not supported by the context");
        }
        if (rescale_bit < 0 || rescale_bit > 120)
        {
            throw invalid_argument("rescale_bit must be in the range [0, 120].");
        }

        // Extract encryption parameters.
        const auto &coeff_modulus = context_.get_context_data(encrypted.parms_id())->parms().coeff_modulus();
        double_t factor = 1.0;

        // Calculate correction factor
        if (nth_rescale == 0 && encrypted.scale() != curr_scale)
        {
            factor = curr_scale / encrypted.scale();
        }

        if (rescale_bit > 60)
        {
            if (encrypted.coeff_modulus_size() < 2ULL * nth_rescale)
            {
                throw invalid_argument("Insufficient modulus levels for double-step rescaling.");
            }

            size_t end_index = encrypted.coeff_modulus_size() - (2ULL * nth_rescale);

            factor *= (static_cast<double_t>(coeff_modulus[end_index - 1ULL].value()) *
                       static_cast<double_t>(coeff_modulus[end_index - 2ULL].value())) /
                      target_scale;
        }
        else
        {
            if (encrypted.coeff_modulus_size() < nth_rescale)
            {
                throw invalid_argument("Insufficient modulus levels for single-step rescaling.");
            }

            size_t end_index = encrypted.coeff_modulus_size() - nth_rescale;

            factor *= static_cast<double_t>(coeff_modulus[end_index - 1ULL].value()) / target_scale;
        }

        return factor;
    }

    void CKKSBootstrapper::dynamic_rescale_inplace(
        Ciphertext &encrypted, const Evaluator &evaluator, int rescale_bit) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.using_bootstrapping())
        {
            throw logic_error("bootstrapping is not supported by the context");
        }
        if (rescale_bit < 0 || rescale_bit > 120)
        {
            throw invalid_argument("rescale_bit must be in the range [0, 120].");
        }

        // Rescale.
        evaluator.rescale_to_next_inplace(encrypted);

        if (rescale_bit > 60)
        {
            evaluator.rescale_to_next_inplace(encrypted);
        }
    }

    void CKKSBootstrapper::print_progress_percent(const string &task_name, size_t curr_step, size_t total_steps) const
    {
        if (curr_step == 0ULL)
        {
            cout << "\r|   " << task_name << ": 0%" << flush;
        }
        else if (curr_step == total_steps)
        {
            cout << "\r|   " << task_name << ": 100%\n" << flush;
        }
        else
        {
            size_t last_pct = static_cast<size_t>(round(static_cast<double>(curr_step - 1) / total_steps * 100.0));
            size_t curr_pct = static_cast<size_t>(round(static_cast<double>(curr_step) / total_steps * 100.0));

            if (last_pct != curr_pct)
            {
                cout << "\r|   " << task_name << ": " << curr_pct << "%" << flush;
            }
        }
    }
} // namespace seal