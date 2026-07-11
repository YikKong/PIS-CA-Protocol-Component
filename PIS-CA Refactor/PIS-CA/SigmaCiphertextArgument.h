#pragma once

#ifndef SIGMA_CIPHERTEXT_ARGUMENT_H
#define SIGMA_CIPHERTEXT_ARGUMENT_H

#include <memory>
#include <vector>

#include <NTL/ZZ.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../Curdleproofs/ElGamalCommitment/ElGamalCommitment.h"
#include "../Curdleproofs/SameMultiScalar Argument/SameMultiScalarArgument.h"
#include "../Curdleproofs/SameSalar Argument/SameScalarArgument.h"
#include "../ElGamal/ElGamalEnc.h"

class SigmaCiphertextArgument
{
public:
    using PublicKey = ElGamalEnc::PublicKey;
    using ArgumentCommitmentKey = ElGamalCommitment::CommitmentKey;
    using BetaCommitmentKey = ElGamalEnc::CommitmentKey;
    using BetaCommitment = ElGamalEnc::Commitment;
    using GroupElement = ElGamalEnc::GroupElement;
    using Ciphertext = ElGamalEnc::Ciphertext;

    struct PublicInstance
    {
        SameScalarArgument::PublicInstance same_scalar;
        SameMultiScalarArgument::PublicInstance same_multi_scalar;
    };

    struct Witness
    {
        std::vector<std::shared_ptr<BIGNUM>> rho;
        std::shared_ptr<BIGNUM> aggregate_rho;
        SameScalarArgument::Witness same_scalar;
        SameMultiScalarArgument::Witness same_multi_scalar;
    };

    struct ProofMessage
    {
        PublicInstance public_instance;
        SameScalarArgument::ProofMessage same_scalar;
        SameMultiScalarArgument::ProofMessage same_multi_scalar;
    };

    struct Proof
    {
        PublicInstance public_instance;
        Witness witness;
        ProofMessage message;
    };

    explicit SigmaCiphertextArgument(const ElGamalEnc& elgamal);
    SigmaCiphertextArgument(const SigmaCiphertextArgument&) = delete;
    SigmaCiphertextArgument& operator=(const SigmaCiphertextArgument&) = delete;
    ~SigmaCiphertextArgument();

    void CreateProof(
        const PublicKey& public_key,
        const ArgumentCommitmentKey& argument_commitment_key,
        const BetaCommitmentKey& beta_commitment_key,
        const std::vector<GroupElement>& g_values,
        const std::vector<BetaCommitment>& beta_commitments,
        const std::vector<std::shared_ptr<BIGNUM>>& beta_commitment_randomness,
        const std::vector<NTL::ZZ>& beta,
        const std::vector<Ciphertext>& sigma_ciphertexts,
        const std::vector<std::shared_ptr<BIGNUM>>& sigma_encryption_randomness,
        Proof& proof) const;

    bool VerifyProof(
        const PublicKey& public_key,
        const ArgumentCommitmentKey& argument_commitment_key,
        const BetaCommitmentKey& beta_commitment_key,
        const std::vector<GroupElement>& g_values,
        const std::vector<BetaCommitment>& beta_commitments,
        const std::vector<Ciphertext>& sigma_ciphertexts,
        const ProofMessage& proof_message) const;

private:
    void BuildPublicData(
        const PublicKey& public_key,
        const ArgumentCommitmentKey& argument_commitment_key,
        const BetaCommitmentKey& beta_commitment_key,
        const std::vector<GroupElement>& g_values,
        const std::vector<BetaCommitment>& beta_commitments,
        const std::vector<Ciphertext>& sigma_ciphertexts,
        std::vector<std::shared_ptr<BIGNUM>>& c_challenges,
        std::vector<std::shared_ptr<BIGNUM>>& d_challenges,
        std::vector<Ciphertext>& ct_g,
        Ciphertext& aggregate_ct_g,
        std::vector<Ciphertext>& weighted_sigma_ciphertexts,
        BetaCommitment& aggregate_beta_commitment,
        std::vector<EC_POINT*>& same_multi_g,
        std::vector<EC_POINT*>& same_multi_h) const;

    bool PublicInstanceMatches(
        const PublicKey& public_key,
        const ArgumentCommitmentKey& argument_commitment_key,
        const PublicInstance& public_instance,
        const Ciphertext& aggregate_ct_g,
        const std::vector<Ciphertext>& weighted_sigma_ciphertexts,
        const BetaCommitment& aggregate_beta_commitment,
        const std::vector<EC_POINT*>& same_multi_g,
        const std::vector<EC_POINT*>& same_multi_h) const;

    void GenerateChallenges(
        const char* label,
        const PublicKey& public_key,
        const BetaCommitmentKey& beta_commitment_key,
        const std::vector<GroupElement>& g_values,
        const std::vector<BetaCommitment>& beta_commitments,
        const std::vector<Ciphertext>& sigma_ciphertexts,
        std::vector<std::shared_ptr<BIGNUM>>& challenges) const;

    void AppendPoint(std::string& transcript, const EC_POINT* point) const;
    void AppendScalar(std::string& transcript, const BIGNUM* scalar) const;
    std::shared_ptr<BIGNUM> ZZToBignum(const NTL::ZZ& value) const;
    std::shared_ptr<BIGNUM> NewScalar(unsigned long value) const;
    std::shared_ptr<BIGNUM> ModNegate(const BIGNUM* value) const;
    bool CiphertextsEqual(const Ciphertext& left, const Ciphertext& right) const;
    bool PointsEqual(const EC_POINT* left, const EC_POINT* right) const;
    std::size_t NextPowerOfTwo(std::size_t value) const;
    void FreePointVector(std::vector<EC_POINT*>& points) const;

    const ElGamalEnc& elgamal_;
    SameScalarArgument same_scalar_;
    SameMultiScalarArgument same_multi_scalar_;
    BN_CTX* bn_ctx_;
};

#endif // SIGMA_CIPHERTEXT_ARGUMENT_H
