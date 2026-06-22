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
    using Commitment = CamenischShoupEnc::Commitment;
    using Ciphertext = CamenischShoupEnc::Ciphertext;

    explicit CamenischShoupEncZKP(const CamenischShoupEnc& encryption);

    struct ProofMessage
    {
        std::vector<Ciphertext> ciphertexts;
        std::vector<Commitment> commitments;
        Ciphertext random_ciphertext;
        Commitment random_commitment;
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
        std::vector<Commitment> commitments;
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
        std::vector<Commitment>& commitments) const;

    void CreateEncProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& encryption_randomness,
        const std::vector<NTL::ZZ>& commitment_randomness,
        const std::vector<Commitment>& commitments,
        Proof& proof) const;

    void CreateEncProofMessage(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& encryption_randomness,
        const std::vector<NTL::ZZ>& commitment_randomness,
        const std::vector<Commitment>& commitments,
        ProofMessage& proof_message) const;

    void GenerateCommitmentsAndEncProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<NTL::ZZ>& encryption_randomness,
        std::vector<NTL::ZZ>& commitment_randomness,
        std::vector<Commitment>& commitments,
        Proof& proof) const;

    bool VerifyEncProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const ProofMessage& proof_message) const;

    bool VerifyEncProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<Commitment>& commitments,
        const ProofMessage& proof_message) const;

    struct BatchBetaProofMessage
    {
        Ciphertext base_ciphertext;
        NTL::ZZ q;
        std::vector<Commitment> a_commitments;
        std::vector<Commitment> alpha_commitments;
        std::vector<Commitment> b_commitments;
        std::vector<Ciphertext> beta_ciphertexts;
        Commitment random_a_commitment;
        Commitment random_alpha_commitment;
        Commitment random_b_commitment;
        Ciphertext random_beta_ciphertext;
        std::vector<NTL::ZZ> challenges;

        // One aggregated response per packed plaintext slot.
        std::vector<NTL::ZZ> a_responses;
        std::vector<NTL::ZZ> alpha_responses;
        std::vector<NTL::ZZ> b_responses;
        NTL::ZZ a_commitment_randomness_response;
        NTL::ZZ alpha_commitment_randomness_response;
        NTL::ZZ b_commitment_randomness_response;
        NTL::ZZ encryption_randomness_response;
    };

    struct BatchBetaProof
    {
        std::vector<NTL::ZZ> a;
        std::vector<NTL::ZZ> alpha;
        std::vector<NTL::ZZ> b;
        std::vector<NTL::ZZ> a_commitment_randomness;
        std::vector<NTL::ZZ> alpha_commitment_randomness;
        std::vector<NTL::ZZ> b_commitment_randomness;
        std::vector<NTL::ZZ> encryption_randomness;
        std::vector<NTL::ZZ> a_masks;
        std::vector<NTL::ZZ> alpha_masks;
        std::vector<NTL::ZZ> b_masks;
        NTL::ZZ a_commitment_randomness_mask;
        NTL::ZZ alpha_commitment_randomness_mask;
        NTL::ZZ b_commitment_randomness_mask;
        NTL::ZZ encryption_randomness_mask;
        BatchBetaProofMessage message;
    };

    void CreateBatchBetaCiphertextsAndProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const Ciphertext& base_ciphertext,
        const NTL::ZZ& q,
        const std::vector<NTL::ZZ>& a,
        const std::vector<NTL::ZZ>& alpha,
        const std::vector<NTL::ZZ>& b,
        const std::vector<NTL::ZZ>& a_commitment_randomness,
        const std::vector<NTL::ZZ>& alpha_commitment_randomness,
        const std::vector<NTL::ZZ>& b_commitment_randomness,
        const std::vector<NTL::ZZ>& encryption_randomness,
        BatchBetaProof& proof) const;

    bool VerifyBatchBetaProof(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const BatchBetaProofMessage& proof_message) const;

private:
    Commitment GenerateCommitment(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& plaintexts,
        const NTL::ZZ& commitment_randomness,
        std::uint32_t batch_index) const;

    NTL::ZZ GenerateChallenge(
        const PublicKey& public_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<Commitment>& commitments,
        const Ciphertext& random_ciphertext,
        const Commitment& random_commitment,
        std::uint32_t challenge_index) const;

    void GenerateChallenges(
        const PublicKey& public_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<Commitment>& commitments,
        const Ciphertext& random_ciphertext,
        const Commitment& random_commitment,
        std::vector<NTL::ZZ>& challenges) const;

    bool HasExpectedSizes(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<Commitment>& commitments) const;

    Commitment GenerateVectorCommitment(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& values,
        const NTL::ZZ& randomness) const;

    NTL::ZZ PackBatchValues(
        const PublicKey& public_key,
        const std::vector<NTL::ZZ>& values) const;

    Ciphertext EvaluateBetaCiphertext(
        const PublicKey& public_key,
        const Ciphertext& base_ciphertext,
        const std::vector<NTL::ZZ>& a,
        const std::vector<NTL::ZZ>& alpha,
        const std::vector<NTL::ZZ>& b,
        const NTL::ZZ& q,
        const NTL::ZZ& encryption_randomness) const;

    NTL::ZZ GenerateBatchBetaChallenge(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const BatchBetaProofMessage& proof_message,
        std::uint32_t output_index) const;

    bool IsValidCiphertext(const PublicKey& public_key, const Ciphertext& ciphertext) const;
    bool IsValidCommitment(const PublicKey& public_key, const Commitment& commitment) const;

    const CamenischShoupEnc& encryption_;
};

#endif // CAMENISCH_SHOUP_ENC_ZKP_H
