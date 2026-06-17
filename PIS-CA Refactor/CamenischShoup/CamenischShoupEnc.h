#pragma once
/* ****************************************************************************************************************************************************************** *\
 * @file    CamenischShoupEnc.h                                                                                                                                       *
 * @brief   Camenisch-Shoup encryption                                                                                                                                *
 *                                                                                                                                                                    *
\* ****************************************************************************************************************************************************************** */

#ifndef CAMENISCH_SHOUP_ENC_H
#define CAMENISCH_SHOUP_ENC_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <NTL/ZZ.h>

class CamenischShoupEnc
{
public:
    static constexpr std::uint32_t HashBytes = 32;
    static constexpr std::uint32_t PrimeBits = 768;
    static constexpr std::uint32_t Zeta = 2;
    static constexpr std::uint32_t PlaintextSlots = 4;
    static constexpr std::uint32_t SubPlaintextLens = 768;
    static constexpr std::uint32_t CiphertextEComponentCount = 1;
    static constexpr std::uint32_t PlaintextValuesPerCiphertext = PlaintextSlots * CiphertextEComponentCount;
    static constexpr std::uint32_t CommitmentGeneratorCount = PlaintextValuesPerCiphertext;
    static constexpr std::uint32_t InputPlaintextCount = 2;

    struct PublicKey
    {
        NTL::ZZ N;
        NTL::ZZ N_prime;
        NTL::ZZ N_zeta_plus_one;
        NTL::ZZ N_zeta;
        NTL::ZZ T;
        NTL::ZZ g;
        std::vector<NTL::ZZ> pk;
        NTL::ZZ plaintext_packing_base;
    };

    struct SecretKey
    {
        std::vector<NTL::ZZ> sk;
    };

    struct CommitmentKey
    {
        std::vector<NTL::ZZ> generators;
        NTL::ZZ h;
    };

    struct Ciphertext
    {
        NTL::ZZ u;
        std::vector<NTL::ZZ> e;
    };

    std::vector<NTL::ZZ> input_plaintexts;
    std::vector<NTL::ZZ> input_encryption_randomness;
    std::vector<Ciphertext> input_ciphertexts;
    std::vector<NTL::ZZ> input_commitment_randomness;
    std::vector<NTL::ZZ> input_commitments;

    void RandomOracle(std::array<std::uint8_t, HashBytes>& challenge, const std::string& input) const;
    void Setup(PublicKey& public_key) const;
    void GenerateKeys(PublicKey& public_key, SecretKey& secret_key, CommitmentKey& commitment_key) const;
    void InitializeInputs(const PublicKey& public_key, const CommitmentKey& commitment_key);
    void Encrypt(const PublicKey& public_key, const std::vector<NTL::ZZ>& plaintext, NTL::ZZ& randomness, Ciphertext& ciphertext) const;
    void EncryptWithRandomness(const PublicKey& public_key, const std::vector<NTL::ZZ>& plaintext, const NTL::ZZ& randomness, Ciphertext& ciphertext) const;
    void LFunction(const PublicKey& public_key, const NTL::ZZ& encoded_value, NTL::ZZ& quotient) const;
    void DiscreteLog(const PublicKey& public_key, const NTL::ZZ& encoded_plaintext, NTL::ZZ& plaintext) const;
    void Decrypt(const PublicKey& public_key, const SecretKey& secret_key, const Ciphertext& ciphertext, std::vector<NTL::ZZ>& plaintext) const;
    void HomomorphicAdd(const PublicKey& public_key, Ciphertext& result, const Ciphertext& left, const Ciphertext& right) const;
    void HomomorphicSubtract(const PublicKey& public_key, Ciphertext& result, const Ciphertext& left, const Ciphertext& right) const;
    void ScalarMultiply(const PublicKey& public_key, Ciphertext& result, const Ciphertext& ciphertext, const NTL::ZZ& scalar) const;

private:
    NTL::ZZ PackPlaintextSlots(const PublicKey& public_key, const std::vector<NTL::ZZ>& plaintext, std::uint32_t component_index) const;
    void UnpackPlaintextSlots(const PublicKey& public_key, NTL::ZZ packed_plaintext, std::vector<NTL::ZZ>& plaintext) const;
    std::vector<NTL::ZZ> PlaintextSlice(const std::vector<NTL::ZZ>& plaintexts, std::uint32_t plaintext_index) const;
    NTL::ZZ GenerateCommitment(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const NTL::ZZ& commitment_randomness,
        std::uint32_t plaintext_index) const;
};

#endif // CAMENISCH_SHOUP_ENC_H
