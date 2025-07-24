// Added by Dice15.

#pragma once

#include "seal/ciphertext.h"
#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/plaintext.h"
#include "seal/relinkeys.h"
#include "seal/secretkey.h"
#include "seal/valcheck.h"
#include "seal/modulus.h"
#include <complex>
#include <string>
#include <vector>

using namespace std;

namespace seal
{
    /**
     * @brief Provides CKKS bootstrapping operations to refresh and reduce noise in CKKS ciphertexts.
     *
     * The CKKSBootstrapper class implements the complete bootstrapping pipeline for the CKKS scheme,
     * including coefficient-to-slot (CTS) and slot-to-coefficient (STC) transformations,
     * approximate modulus reduction, and dynamic rescaling with automatic scale and modulus management.
     */
    class CKKSBootstrapper
    {
    public:
        /**
         * @brief Constructs a CKKSBootstrapper instance and precomputes rotation and diagonal matrices.
         * @param[in] context SEALContext containing encryption parameters; must support CKKS bootstrapping.
         * @throws logic_error if bootstrapping is not enabled in the context.
         * @throws invalid_argument if the scheme is not CKKS.
         */
        CKKSBootstrapper(const SEALContext &context);
        
        /**
         * @brief Computes the required bootstrapping depth for given parameters.
         * @param[in] delta_bit_size Bit-size of the scaling factor applied during modulus switching.
         * @param[in] encrypted_level Index (l) of the target modulus level in the modulus chain.
         * @param[in] d_0 Degree parameter for Taylor series approximation (must be >= 1).
         * @param[in] r Number of exponentiation rounds (power-of-two exponent).
         * @return Total depth consumption as a size_t.
         * @throws invalid_argument if d_0 < 1.
         */
        static size_t get_bootstrap_depth(int delta_bit_size, size_t encrypted_level, size_t d_0, size_t r);

        /**
         * @brief Extends and selects primes for the coefficient modulus chain to support bootstrapping.
         * @param[in] poly_modulus_degree Polynomial modulus degree (n).
         * @param[in] coeff_modulus_bit_sizes Initial vector of prime bit-sizes (must contain at least two primes).
         * @param[in] delta_bit_size Bit-size for modulus-switching operations.
         * @param[in] encrypted_level Index up to which original moduli are preserved (l).
         * @param[in] d_0 Degree parameter for Taylor polynomial approximation (must be >= 1).
         * @param[in] r Number of squaring rounds for exponentiation in bootstrapping.
         * @return Extended vector of Modulus objects for the new coefficient modulus chain.
         * @throws invalid_argument if coeff_modulus_bit_sizes.size() < 2,
         *         delta_bit_size not in [0, 120],
         *         encrypted_level + 1 > coeff_modulus_bit_sizes.size(),
         *         or d_0 < 1.
         */
        static vector<Modulus> create_coeff_modulus(
            size_t poly_modulus_degree, vector<int> coeff_modulus_bit_sizes, int delta_bit_size, size_t encrypted_level,
            size_t d_0, size_t r);

        /**
         * @brief Generates the necessary Galois rotation steps for CKKS bootstrapping based on the polynomial modulus degree and optional custom steps.
         * @param[in] poly_modulus_degree The polynomial modulus degree (n), must be a power of two >= 2.
         * @param[in] steps A vector of user-defined rotation steps (default: empty).
         * @return A vector of unique integer Galois steps required for bootstrapping.
         */
        static vector<int> create_galois_steps(size_t poly_modulus_degree, const vector<int> &steps = {});

        /**
         * @brief Runs CKKS bootstrapping on an input ciphertext to refresh noise and reset level.
         * @param[in] encrypted Input ciphertext to bootstrap.
         * @param[in] encoder CKKSEncoder instance for plaintext encoding/decoding.
         * @param[in] evaluator Evaluator for homomorphic operations.
         * @param[in] relin_keys Relinearization keys for multiplication.
         * @param[in] galois_keys Galois keys for rotations.
         * @param[in] delta_bit_size Bit-size parameter used during approximate modulus reduction.
         * @param[in] encrypted_level Index (l) of modulus level for intermediate modulus-switching.
         * @param[in] d_0 Degree parameter for Taylor series expansion (must be >= 1).
         * @param[in] r Number of squaring rounds in the exponentiation step.
         * @param[out] destination Output ciphertext after bootstrapping.
         * @param[in] print_progress Whether to print progress percentages and timing.
         * @throws invalid_argument for invalid parameters, metadata mismatches, or delta_bit_size/d_0 out of range.
         * @throws logic_error if context does not support bootstrapping or bootstrapping_depth mismatches.
         */
        void bootstrapping(
            const Ciphertext &encrypted, const CKKSEncoder &encoder, const Evaluator &evaluator,
            const RelinKeys &relin_keys, const GaloisKeys &galois_keys, int delta_bit_size, size_t encrypted_level,
            size_t d_0, size_t r, Ciphertext &destination, bool print_progress = false) const;

    private:
        /**
         * @brief Transforms a ciphertext from coefficient to slot representation (CTS).
         * @param[in] encrypted Input ciphertext in coefficient form.
         * @param[in] encoder CKKSEncoder instance for plaintext operations.
         * @param[in] evaluator Evaluator for homomorphic operations.
         * @param[in] scale Current scale value of the ciphertext.
         * @param[in] delta_bit_size Bit-size parameter for rescaling operations.
         * @param[in] galois_keys Galois keys for vector rotations.
         * @param[out] destination1 First output ciphertext after CTS.
         * @param[out] destination2 Second output ciphertext after CTS.
         * @param[in] print_progress Whether to print CTS progress.
         */
        void coeff_to_slot(
            const Ciphertext &encrypted, const CKKSEncoder &encoder, const Evaluator &evaluator, double_t scale,
            int delta_bit_size, const GaloisKeys &galois_keys, Ciphertext &destination1, Ciphertext &destination2,
            bool print_progress = false) const;

        /**
         * @brief Transforms ciphertexts from slot to coefficient representation (STC).
         * @param[in] encrypted1 First input ciphertext in slot form.
         * @param[in] encrypted2 Second input ciphertext in slot form.
         * @param[in] encoder CKKSEncoder instance for plaintext operations.
         * @param[in] evaluator Evaluator for homomorphic operations.
         * @param[in] scale Target scale value after STC.
         * @param[in] delta_bit_size Bit-size parameter used for rescaling operations.
         * @param[in] galois_keys Galois keys for rotations.
         * @param[out] destination Output ciphertext in coefficient form.
         * @param[in] print_progress Whether to print STC progress.
         */
        void slot_to_coeff(
            const Ciphertext &encrypted1, const Ciphertext &encrypted2, const CKKSEncoder &encoder,
            const Evaluator &evaluator, double_t scale, int delta_bit_size, const GaloisKeys &galois_keys,
            Ciphertext &destination, bool print_progress = false) const;

        /**
         * @brief Performs approximate modulus reduction to level q_l on two half-ciphertexts.
         * @param[in] encrypted1 First ciphertext component to reduce.
         * @param[in] encrypted2 Second ciphertext component to reduce.
         * @param[in] encoder CKKSEncoder instance for plaintext operations.
         * @param[in] evaluator Evaluator for homomorphic operations.
         * @param[in] relin_keys Relinearization keys for multiplication.
         * @param[in] galois_keys Galois keys for rotations.
         * @param[in] delta_bit_size Bit-size parameter used for scale in reduction.
         * @param[in] encrypted_level Target index (l) in the modulus chain for q_l.
         * @param[in] d_0 Degree parameter for the Taylor series (must be >= 1).
         * @param[in] r Number of exponentiation rounds in the reduction step.
         * @param[out] destination1 First output ciphertext after reduction.
         * @param[out] destination2 Second output ciphertext after reduction.
         * @param[in] print_progress Whether to print progress percentages.
         */
        void approximate_mod_q_l(
            const Ciphertext &encrypted1, const Ciphertext &encrypted2, const CKKSEncoder &encoder,
            const Evaluator &evaluator, const RelinKeys &relin_keys, const GaloisKeys &galois_keys, int delta_bit_size,
            size_t encrypted_level, size_t d_0, size_t r, Ciphertext &destination1, Ciphertext &destination2,
            bool print_progress = false) const;

        /**
         * @brief Computes dynamic correction factor for scale adjustment after rescaling.
         * @tparam T Numeric type (double or complex<double>).
         * @param[in] value Initial value to apply the correction factor to.
         * @param[in] encrypted Ciphertext whose metadata is used for correction.
         * @param[in] curr_scale Expected current scale before correction.
         * @param[in] target_scale Desired scale after correction.
         * @param[in] rescale_bit_size Bit-size parameter controlling single or double-step rescaling.
         * @param[in] nth_rescale Number of rescaling operations already applied.
         * @return Multiplicative correction factor of type T.
         * @throws invalid_argument for invalid input metadata or insufficient modulus levels.
         * @throws logic_error if bootstrapping is not supported by the context.
         */
        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        T apply_dynamic_correction_factor(
            T value, const Ciphertext &encrypted, double_t curr_scale, double_t target_scale, int rescale_bit_size,
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
            if (rescale_bit_size < 0 || rescale_bit_size > 120)
            {
                throw invalid_argument("rescale_bit_size must be in the range [0, 120]");
            }

            // Extract encryption parameters.
            const auto &coeff_modulus = context_.get_context_data(encrypted.parms_id())->parms().coeff_modulus();
            T factor = value;

            // Calculate correction factor
            if (nth_rescale == 0 && encrypted.scale() != curr_scale)
            {
                factor *= curr_scale / encrypted.scale();
            }

            if (rescale_bit_size > 60)
            {
                if (encrypted.coeff_modulus_size() < 2ULL * nth_rescale)
                {
                    throw invalid_argument("Insufficient modulus levels for double-step rescaling.");
                }

                size_t end_index = encrypted.coeff_modulus_size() - (2ULL * nth_rescale);
                double_t small_scale = sqrt(target_scale);
                factor *= static_cast<double_t>(coeff_modulus[end_index - 1ULL].value()) / small_scale;
                factor *= static_cast<double_t>(coeff_modulus[end_index - 2ULL].value()) / small_scale;
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

        /**
         * @brief Rescales a ciphertext in-place, with optional double-step for large rescale_bit_size.
         * @param[in,out] encrypted Ciphertext to rescale.
         * @param[in] evaluator Evaluator for homomorphic rescaling.
         * @param[in] rescale_bit_size Bit-size controlling single or double rescaling.
         * @throws invalid_argument if metadata is invalid or rescale_bit_size is out of range.
         * @throws logic_error if bootstrapping is not supported by the context.
         */
        void dynamic_rescale_inplace(Ciphertext &encrypted, const Evaluator &evaluator, int rescale_bit_size) const;

        /**
         * @brief Prints a progress percentage for a named task.
         * @param[in] task_name Identifier for the current stage (e.g., "CTS", "STC").
         * @param[in] curr_step Current step count.
         * @param[in] total_steps Total number of steps.
         */
        void print_progress_percent(const string &task_name, size_t curr_step, size_t total_steps) const;

        SEALContext context_;

        vector<vector<complex<double_t>>> U0_diag_;

        vector<vector<complex<double_t>>> U1_diag_;

        vector<vector<complex<double_t>>> U0_t_diag_;

        vector<vector<complex<double_t>>> U1_t_diag_;

        vector<vector<complex<double_t>>> U0_t_c_diag_;

        vector<vector<complex<double_t>>> U1_t_c_diag_;

        double_t PI_ = 3.1415926535897932384626433832795028842;
    };
} // namespace seal
