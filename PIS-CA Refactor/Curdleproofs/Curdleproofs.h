#pragma once

#ifndef CURDLEPROOFS_H
#define CURDLEPROOFS_H

#include <cstddef>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "ElGamalCommitment/ElGamalCommitment.h"
#include "SameMultiScalar Argument/SameMultiScalarArgument.h"
#include "SamePermutation Argument/SamePermutationArgument.h"
#include "SameSalar Argument/SameScalarArgument.h"
#include "../ElGamal/ElGamalEnc.h"

class Curdleproofs
{
public:
    using PublicKey = ElGamalEnc::PublicKey;
    using Ciphertext = ElGamalEnc::Ciphertext;
    using CommitmentKey = ElGamalCommitment::CommitmentKey;

    struct PublicInstance
    {
        std::vector<Ciphertext> output_ciphertexts;
        SameScalarArgument::PublicInstance same_scalar;
        SamePermutationArgument::PublicInstance same_permutation;
        SameMultiScalarArgument::PublicInstance same_multi_scalar;
    };

    struct Witness
    {
        SameScalarArgument::Witness same_scalar;
        SamePermutationArgument::Witness same_permutation;
        SameMultiScalarArgument::Witness same_multi_scalar;
    };

    struct ProofMessage
    {
        SameScalarArgument::ProofMessage same_scalar;
        SamePermutationArgument::ProofMessage same_permutation;
        SameMultiScalarArgument::ProofMessage same_multi_scalar;
    };

    struct Proof
    {
        PublicInstance public_instance;
        Witness witness;
        ProofMessage message;
    };

    explicit Curdleproofs(const ElGamalEnc& elgamal);
    Curdleproofs(const Curdleproofs&) = delete;
    Curdleproofs& operator=(const Curdleproofs&) = delete;
    ~Curdleproofs();

    void GenerateChallengeVector(
        std::size_t size,
        std::vector<BIGNUM*>& challenge_vector) const;

    void GeneratePermutation(
        std::size_t size,
        std::vector<std::size_t>& permutation) const;

    void RerandomizeCiphertexts(
        const PublicKey& public_key,
        const std::vector<Ciphertext>& ciphertexts,
        BIGNUM* rerandomization_scalar,
        std::vector<Ciphertext>& rerandomized_ciphertexts) const;

    void RerandomizeCiphertextsWithScalars(
        const PublicKey& public_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<BIGNUM*>& rerandomization_scalars,
        std::vector<Ciphertext>& rerandomized_ciphertexts) const;

    void PermuteCiphertexts(
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<std::size_t>& permutation,
        std::vector<Ciphertext>& permuted_ciphertexts) const;

    void InitializePublicInstance(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<Ciphertext>& ciphertexts,
        PublicInstance& public_instance,
        Witness& witness) const;

    void InitializeKnownRerandomizedShuffle(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<BIGNUM*>& rerandomization_scalars,
        const std::vector<std::size_t>& permutation,
        PublicInstance& public_instance,
        Witness& witness) const;

    void CreateProof(
        const CommitmentKey& commitment_key,
        const PublicInstance& public_instance,
        const Witness& witness,
        Proof& proof) const;

    bool VerifyProof(
        const CommitmentKey& commitment_key,
        const PublicInstance& public_instance,
        const ProofMessage& proof_message) const;

    bool VerifyProof(
        const CommitmentKey& commitment_key,
        const Proof& proof) const;

private:
    void SplitScalar(
        const BIGNUM* scalar,
        std::size_t parts,
        std::vector<BIGNUM*>& shares) const;

    void BuildRepeatedPointVector(
        const EC_POINT* point,
        std::size_t size,
        std::vector<EC_POINT*>& points) const;

    bool IsValidPermutation(
        const std::vector<std::size_t>& permutation,
        std::size_t size) const;

    const ElGamalEnc& elgamal_;
    SameScalarArgument same_scalar_;
    SamePermutationArgument same_permutation_;
    SameMultiScalarArgument same_multi_scalar_;
    BN_CTX* bn_ctx_;
};

#endif // CURDLEPROOFS_H
