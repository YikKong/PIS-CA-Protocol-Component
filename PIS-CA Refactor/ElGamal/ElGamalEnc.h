#pragma once
/* ****************************************************************************************************************************************************************** *\
 * @file    ElGamalEnc.h                                                                                                                                              *
 * @brief   Additively homomorphic elliptic-curve ElGamal encryption                                                                                                  *
 *                                                                                                                                                                    *
\* ****************************************************************************************************************************************************************** */

#ifndef ELGAMAL_ENC_H
#define ELGAMAL_ENC_H

#include <array>
#include <cstdint>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

class ElGamalEnc
{
public:
    static constexpr std::uint32_t HashBytes = 32;

    struct PublicKey
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* generator = nullptr;
        EC_POINT* g = nullptr;
        EC_POINT* pk = nullptr;

        PublicKey() = default;
        PublicKey(const PublicKey& other);
        PublicKey& operator=(const PublicKey& other);
        PublicKey(PublicKey&& other) noexcept;
        PublicKey& operator=(PublicKey&& other) noexcept;
        ~PublicKey();
    };

    struct SecretKey
    {
        BIGNUM* sk = nullptr;

        SecretKey();
        SecretKey(const SecretKey& other);
        SecretKey& operator=(const SecretKey& other);
        SecretKey(SecretKey&& other) noexcept;
        SecretKey& operator=(SecretKey&& other) noexcept;
        ~SecretKey();
    };

    struct CommitmentKey
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* g = nullptr;
        EC_POINT* h = nullptr;

        CommitmentKey() = default;
        CommitmentKey(const CommitmentKey& other);
        CommitmentKey& operator=(const CommitmentKey& other);
        CommitmentKey(CommitmentKey&& other) noexcept;
        CommitmentKey& operator=(CommitmentKey&& other) noexcept;
        ~CommitmentKey();
    };

    struct Commitment
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* value = nullptr;

        Commitment() = default;
        Commitment(const Commitment& other);
        Commitment& operator=(const Commitment& other);
        Commitment(Commitment&& other) noexcept;
        Commitment& operator=(Commitment&& other) noexcept;
        ~Commitment();
    };

    struct Ciphertext
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* u = nullptr;
        EC_POINT* e = nullptr;

        Ciphertext() = default;
        Ciphertext(const Ciphertext& other);
        Ciphertext& operator=(const Ciphertext& other);
        Ciphertext(Ciphertext&& other) noexcept;
        Ciphertext& operator=(Ciphertext&& other) noexcept;
        ~Ciphertext();
    };

    explicit ElGamalEnc(int curve_nid = NID_X9_62_prime256v1);
    ElGamalEnc(const ElGamalEnc&) = delete;
    ElGamalEnc& operator=(const ElGamalEnc&) = delete;
    ~ElGamalEnc();

    void RandomOracle(
        std::array<std::uint8_t, HashBytes>& challenge,
        const std::string& input) const;

    void Setup(PublicKey& public_key) const;
    void GenerateKeys(PublicKey& public_key, SecretKey& secret_key) const;
    void GenerateKeys(
        PublicKey& public_key,
        SecretKey& secret_key,
        CommitmentKey& commitment_key) const;
    void GenerateRandomScalar(BIGNUM* scalar) const;
    void GenerateRandomGroupElement(EC_POINT* point) const;

    // Com(m; rho) = m * commitment_key.g + rho * commitment_key.h.
    void GenerateCommitment(
        const CommitmentKey& commitment_key,
        const BIGNUM* plaintext,
        BIGNUM* randomness,
        Commitment& commitment) const;
    void GenerateCommitmentWithRandomness(
        const CommitmentKey& commitment_key,
        const BIGNUM* plaintext,
        const BIGNUM* randomness,
        Commitment& commitment) const;

    // Enc(pk, M; r) = (r * g, M + r * pk).
    void Encrypt(
        const PublicKey& public_key,
        const EC_POINT* plaintext,
        BIGNUM* randomness,
        Ciphertext& ciphertext) const;
    void EncryptWithRandomness(
        const PublicKey& public_key,
        const EC_POINT* plaintext,
        const BIGNUM* randomness,
        Ciphertext& ciphertext) const;
    void Decrypt(
        const PublicKey& public_key,
        const SecretKey& secret_key,
        const Ciphertext& ciphertext,
        EC_POINT* plaintext) const;

    // Encodes an integer m as the curve point m * g.
    void EncodePlaintext(
        const PublicKey& public_key,
        const BIGNUM* scalar,
        EC_POINT* plaintext) const;

    void HomomorphicAdd(
        const PublicKey& public_key,
        Ciphertext& result,
        const Ciphertext& left,
        const Ciphertext& right) const;
    void HomomorphicSubtract(
        const PublicKey& public_key,
        Ciphertext& result,
        const Ciphertext& left,
        const Ciphertext& right) const;
    void ScalarMultiply(
        const PublicKey& public_key,
        Ciphertext& result,
        const Ciphertext& ciphertext,
        const BIGNUM* scalar) const;

    bool IsValidPublicKey(const PublicKey& public_key) const;
    bool IsValidCommitmentKey(const CommitmentKey& commitment_key) const;
    bool IsValidCommitment(const Commitment& commitment) const;
    bool IsValidCiphertext(const Ciphertext& ciphertext) const;
    bool PointsEqual(const EC_POINT* left, const EC_POINT* right) const;

    const EC_GROUP* Group() const;
    const BIGNUM* Order() const;
    EC_POINT* NewPoint() const;

private:
    void PrepareCommitment(Commitment& commitment) const;
    void PrepareCiphertext(Ciphertext& ciphertext) const;
    void NormalizeScalar(const BIGNUM* scalar, BIGNUM* normalized) const;

    EC_GROUP* group_;
    BN_CTX* bn_ctx_;
    BIGNUM* order_;
};

#endif // ELGAMAL_ENC_H
