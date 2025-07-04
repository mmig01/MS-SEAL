// Added by Dice15. (for CKKS bootstrapping.)

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
#include <complex>
#include <string>
#include <vector>

namespace seal
{
    /**
    @brief Provides CKKS bootstrapping operations to refresh and reduce noise in CKKS ciphertexts.

    The CKKSBootstrapper class implements the complete bootstrapping pipeline for the CKKS scheme,
    including coefficient-to-slot (CTS) and slot-to-coefficient (STC) transformations, approximate
    modulus reduction, and dynamic rescaling with automatic scale and modulus management.
    */
    class CKKSBootstrapper
    {
    public:
        /**
        @brief Constructs a CKKSBootstrapper instance and precomputes rotation and diagonal matrices.
        @param[in] context SEALContext containing encryption parameters; must support CKKS bootstrapping.
        @throws std::logic_error if bootstrapping is not enabled in the context.
        @throws std::invalid_argument if the underlying scheme is not CKKS.
        */
        CKKSBootstrapper(const SEALContext &context);

        /**
        @brief Computes the required bootstrapping depth for given parameters.
        @param[in] delta_bit Bit-size of the scaling factor applied during modulus switching.
        @param[in] l Index of the target modulus in the modulus chain.
        @param[in] d_0 Degree parameter for Taylor series approximation (d_0 >= 1).
        @param[in] r Number of exponentiation rounds (power-of-two exponent).
        @return Total depth consumption as size_t.
        @throws std::invalid_argument if d_0 < 1.
        */
        static size_t get_bootstrap_depth(int delta_bit, size_t l, size_t d_0, size_t r);

        /**
        @brief Extends and selects primes for the coefficient modulus chain to support bootstrapping.
        @param[in] coeff_modulus Initial vector of prime bit-sizes (must contain at least two primes).
        @param[in] scale_bit Bit-size for the CKKS scale.
        @param[in] delta_bit Bit-size for modulus-switching operations.
        @param[in] l Index up to which original moduli are preserved (l + 1 total levels).
        @param[in] d_0 Degree for Taylor polynomial approximation.
        @param[in] r Number of squaring rounds for exponentiation in bootstrapping.
        @return Vector of bit-sizes for the extended coefficient modulus chain (including p).
        @throws std::invalid_argument if coeff_modulus.size() < 2, d_0 < 1, or delta_bit not in [0,120].
        */
        static std::vector<int> create_coeff_modulus(
            std::vector<int> coeff_modulus, int scale_bit, int delta_bit, std::size_t l, std::size_t d_0,
            std::size_t r);

        /**
        @brief Runs CKKS bootstrapping on an input ciphertext to refresh noise and reset level.
        @param[in] encrypted Input ciphertext to bootstrap.
        @param[in] encoder Encoder for plaintext-ciphertext conversions.
        @param[in] encryptor Encryptor for fresh encryption operations.
        @param[in] evaluator Evaluator for homomorphic operations.
        @param[in] relin_keys Relinearization keys for multiplication.
        @param[in] galois_keys Galois keys for rotations.
        @param[in] scale_bit Bit-size of target scale after rescaling.
        @param[in] delta_bit Bit-size used during approximate modulus reduction.
        @param[in] l Index of modulus level for intermediate modulus-switching.
        @param[in] d_0 Degree parameter for Taylor series expansion.
        @param[in] r Number of squaring rounds in the exponentiation step.
        @param[out] destination Output ciphertext after bootstrapping.
        @param[in] print_progress Whether to print progress percentages and timing.
        @throws std::invalid_argument for invalid input parameters or metadata mismatch.
        @throws std::logic_error if context bootstrapping_depth does not match parameters.
        */
        void bootstrapping(
            const Ciphertext &encrypted, const CKKSEncoder &encoder, const Encryptor &encryptor,
            const Evaluator &evaluator, const RelinKeys &relin_keys, const GaloisKeys &galois_keys, int scale_bit,
            int delta_bit, std::size_t l, std::size_t d_0, std::size_t r, Ciphertext &destination,
            bool print_progress = false) const;

    private:
        /**
        @brief Transforms a ciphertext from coefficient representation to slot representation (CTS).
        @param[in] encrypted Input ciphertext in coefficient form.
        @param[in] encoder Encoder instance for plaintext operations.
        @param[in] evaluator Evaluator for homomorphic operations.
        @param[in] scale_bit Bit-size of the current scale.
        @param[in] delta_bit Bit-size for rescaling operations.
        @param[in] galois_keys Galois keys for vector rotations.
        @param[out] destination1 First output ciphertext after CTS.
        @param[out] destination2 Second output ciphertext after CTS.
        @param[in] print_progress Toggle printing of CTS progress.
        */
        void coeff_to_slot(
            const Ciphertext &encrypted, const CKKSEncoder &encoder, const Evaluator &evaluator, int scale_bit,
            int delta_bit, const GaloisKeys &galois_keys, Ciphertext &destination1, Ciphertext &destination2,
            bool print_progress = false) const;

        /**
        @brief Transforms ciphertexts from slot representation back to coefficient representation (STC).
        @param[in] encrypted1 First input ciphertext in slot form.
        @param[in] encrypted2 Second input ciphertext in slot form.
        @param[in] encoder Encoder for plaintext conversions.
        @param[in] evaluator Evaluator for homomorphic operations.
        @param[in] scale_bit Bit-size of the target scale.
        @param[in] delta_bit Bit-size used for rescaling.
        @param[in] galois_keys Galois keys for rotations.
        @param[out] destination Output ciphertext in coefficient form.
        @param[in] print_progress Toggle printing of STC progress.
        */
        void slot_to_coeff(
            const Ciphertext &encrypted1, const Ciphertext &encrypted2, const CKKSEncoder &encoder,
            const Evaluator &evaluator, int scale_bit, int delta_bit, const GaloisKeys &galois_keys,
            Ciphertext &destination, bool print_progress = false) const;

        /**
        @brief Performs approximate modulus reduction to level q_l on two half-ciphertexts.
        @param[in] encrypted1 First ciphertext component to reduce.
        @param[in] encrypted2 Second ciphertext component to reduce.
        @param[in] encoder Encoder for plaintext operations.
        @param[in] encryptor Encryptor for fresh plaintext encryption.
        @param[in] evaluator Evaluator for homomorphic operations.
        @param[in] relin_keys Relinearization keys for multiplication.
        @param[in] galois_keys Galois keys for rotations.
        @param[in] delta_bit Bit-size for the scale used in reduction.
        @param[in] l Target index in modulus chain for q_l.
        @param[in] d_0 Degree parameter for the Taylor series.
        @param[in] r Number of exponentiation rounds.
        @param[out] destination1 First output after reduction.
        @param[out] destination2 Second output after reduction.
        @param[in] print_progress Toggle printing of progress indicators.
        */
        void approximate_mod_q_l(
            const Ciphertext &encrypted1, const Ciphertext &encrypted2, const CKKSEncoder &encoder,
            const Encryptor &encryptor, const Evaluator &evaluator, const RelinKeys &relin_keys,
            const GaloisKeys &galois_keys, int delta_bit, std::size_t l, std::size_t d_0, std::size_t r,
            Ciphertext &destination1, Ciphertext &destination2, bool print_progress = false) const;

        /**
        @brief Computes dynamic correction factor for scale adjustment after rescaling.
        @param[in] cipher Ciphertext whose scale is to be corrected.
        @param[in] curr_scale Expected current scale before correction.
        @param[in] target_scale Desired scale after correction.
        @param[in] rescale_bit Bit-size parameter controlling double-step rescaling.
        @param[in] nth_rescale Number of rescaling operations already applied.
        @return Multiplicative correction factor as double_t.
        @throws std::invalid_argument for invalid metadata or insufficient modulus levels.
        */
        double_t dynamic_correction_factor(
            const Ciphertext &cipher, double_t curr_scale, double_t target_scale, int rescale_bit,
            size_t nth_rescale) const;

        /**
        @brief Rescales a ciphertext in-place, with optional double-step for large rescale_bit.
        @param[in,out] cipher Ciphertext to rescale.
        @param[in] evaluator Evaluator for homomorphic rescaling.
        @param[in] rescale_bit Bit-size controlling single or double rescaling.
        @throws std::invalid_argument if metadata is invalid or context does not support bootstrapping.
        */
        void dynamic_rescale_inplace(Ciphertext &cipher, const Evaluator &evaluator, int rescale_bit) const;

        /**
        @brief Prints a progress percentage for a named task.
        @param[in] task_name Identifier for the current stage (e.g., "CTS", "STC").
        @param[in] curr_step Current step count.
        @param[in] total_steps Total number of steps.
        */
        void print_progress_percent(const std::string &task_name, size_t curr_step, size_t total_steps) const;

        SEALContext context_;

        std::vector<std::vector<std::complex<double_t>>> U0_diag_;

        std::vector<std::vector<std::complex<double_t>>> U1_diag_;

        std::vector<std::vector<std::complex<double_t>>> U0_t_diag_;

        std::vector<std::vector<std::complex<double_t>>> U1_t_diag_;

        std::vector<std::vector<std::complex<double_t>>> U0_t_c_diag_;

        std::vector<std::vector<std::complex<double_t>>> U1_t_c_diag_;

        double_t PI_ = 3.1415926535897932384626433832795028842;
    };
} // namespace seal
