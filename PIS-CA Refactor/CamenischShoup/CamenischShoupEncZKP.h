#pragma once

#ifndef CAMENISCH_SHOUP_ENC_ZKP_H
#define CAMENISCH_SHOUP_ENC_ZKP_H

#include <array>
#include <cstdint>
#include <vector>

#include <NTL/ZZ.h>

#include "CamenischShoupEnc.h"

class CamenischShoupEncZKP
{
public:
    using PublicKey = CamenischShoupEnc::PublicKey;
    using CommitmentKey = CamenischShoupEnc::CommitmentKey;
    using Ciphertext = CamenischShoupEnc::Ciphertext;

    explicit CamenischShoupEncZKP(const CamenischShoupEnc& encryption);

    struct ProofMessage
    {
        std::vector<Ciphertext> ciphertexts;
        std::vector<NTL::ZZ> commitments;
        Ciphertext random_ciphertext;
        NTL::ZZ random_commitment;
        std::vector<NTL::ZZ> challenges;
        std::vector<NTL::ZZ> plaintext_randomness_responses;
        NTL::ZZ commitment_randomness_response;
        NTL::ZZ encryption_randomness_response;
    };

    struct Proof
    {
        std::vector<NTL::ZZ> plaintexts;
        std::vector<Ciphertext> ciphertexts;
        std::vector<NTL::ZZ> encryption_randomness;
        std::vector<NTL::ZZ> commitments;
        std::vector<NTL::ZZ> commitment_randomness;
        std::vector<NTL::ZZ> plaintext_randomness;
        NTL::ZZ encryption_randomness_mask;
        NTL::ZZ commitment_randomness_mask;
        ProofMessage message;
    };

    void GenerateCommitments(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const std::vector<NTL::ZZ>& commitment_randomness,
        std::vector<NTL::ZZ>& commitments) const;

    void CreateProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& encryption_randomness,
        const std::vector<NTL::ZZ>& commitment_randomness,
        const std::vector<NTL::ZZ>& commitments,
        Proof& proof) const;

    void CreateProofMessage(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& encryption_randomness,
        const std::vector<NTL::ZZ>& commitment_randomness,
        const std::vector<NTL::ZZ>& commitments,
        ProofMessage& proof_message) const;

    void GenerateCommitmentsAndProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& encryption_randomness,
        std::vector<NTL::ZZ>& commitment_randomness,
        std::vector<NTL::ZZ>& commitments,
        Proof& proof) const;

    bool VerifyProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const ProofMessage& proof_message) const;

    bool VerifyProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& commitments,
        const ProofMessage& proof_message) const;

private:
    NTL::ZZ GenerateCommitment(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const NTL::ZZ& commitment_randomness,
        std::uint32_t batch_index) const;

    NTL::ZZ GenerateChallenge(
        const PublicKey& public_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& commitments,
        const Ciphertext& random_ciphertext,
        const NTL::ZZ& random_commitment,
        std::uint32_t challenge_index) const;

    void GenerateChallenges(
        const PublicKey& public_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& commitments,
        const Ciphertext& random_ciphertext,
        const NTL::ZZ& random_commitment,
        std::vector<NTL::ZZ>& challenges) const;

    bool HasExpectedSizes(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& commitments) const;

    const CamenischShoupEnc& encryption_;
};

#endif // CAMENISCH_SHOUP_ENC_ZKP_H
