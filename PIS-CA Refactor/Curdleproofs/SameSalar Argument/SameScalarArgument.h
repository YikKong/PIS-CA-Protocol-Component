#pragma once

#ifndef SAME_SCALAR_ARGUMENT_H
#define SAME_SCALAR_ARGUMENT_H

#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../ElGamalCommitment/ElGamalCommitment.h"
#include "../../ElGamal/ElGamalEnc.h"

class SameScalarArgument
{
public:
    using CommitmentKey = ElGamalCommitment::CommitmentKey;
    using Commitment = ElGamalCommitment::Commitment;
    using PublicKey = ElGamalEnc::PublicKey;
    using Ciphertext = ElGamalEnc::Ciphertext;

    struct PublicInstance
    {
        const EC_GROUP* group = nullptr;
        std::vector<Ciphertext> ciphertexts;
        std::vector<BIGNUM*> a;
        EC_POINT* u = nullptr;
        EC_POINT* e = nullptr;
        EC_POINT* u_a_sum = nullptr;
        EC_POINT* e_a_sum = nullptr;
        Commitment cm_u;
        Commitment cm_e;

        PublicInstance() = default;
        PublicInstance(const PublicInstance& other);
        PublicInstance& operator=(const PublicInstance& other);
        PublicInstance(PublicInstance&& other) noexcept;
        PublicInstance& operator=(PublicInstance&& other) noexcept;
        ~PublicInstance();
    };

    struct Witness
    {
        BIGNUM* k = nullptr;
        BIGNUM* r_u = nullptr;
        BIGNUM* r_e = nullptr;
        BIGNUM* k_randomness = nullptr;
        BIGNUM* r_u_randomness = nullptr;
        BIGNUM* r_e_randomness = nullptr;

        Witness();
        Witness(const Witness& other);
        Witness& operator=(const Witness& other);
        Witness(Witness&& other) noexcept;
        Witness& operator=(Witness&& other) noexcept;
        ~Witness();
    };

    struct ProofMessage
    {
        Commitment random_u_commitment;
        Commitment random_e_commitment;
        BIGNUM* k_response = nullptr;
        BIGNUM* r_u_response = nullptr;
        BIGNUM* r_e_response = nullptr;

        ProofMessage();
        ProofMessage(const ProofMessage& other);
        ProofMessage& operator=(const ProofMessage& other);
        ProofMessage(ProofMessage&& other) noexcept;
        ProofMessage& operator=(ProofMessage&& other) noexcept;
        ~ProofMessage();
    };

    struct Proof
    {
        PublicInstance public_instance;
        Witness witness;
        ProofMessage message;
    };

    explicit SameScalarArgument(const ElGamalEnc& elgamal);
    SameScalarArgument(const SameScalarArgument&) = delete;
    SameScalarArgument& operator=(const SameScalarArgument&) = delete;
    ~SameScalarArgument();

    // SameScalar argument:
    // public instance = (ciphertexts, a, u, e, cm_u, cm_e)
    // witness = (k, r_u, r_e, k_randomness, r_u_randomness, r_e_randomness)
    // sum_a = a[0] + ... + a[n - 1]
    // u_a_sum = g^sum_a, e_a_sum = pk^sum_a
    // u = ciphertexts[0].u^a[0] * ... * ciphertexts[n - 1].u^a[n - 1]
    // e = ciphertexts[0].e^a[0] * ... * ciphertexts[n - 1].e^a[n - 1]
    // cm_u = GroupCommit((GU, H); u * u_a_sum^k; r_u)
    // cm_e = GroupCommit((GE, H); e * e_a_sum^k; r_e)
    void InitializePublicInstance(
        const PublicKey& public_key,
        const CommitmentKey& commitment_key,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<BIGNUM*>& a,
        const BIGNUM* k,
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
    void GenerateChallenge(
        const CommitmentKey& commitment_key,
        const PublicInstance& public_instance,
        const ProofMessage& proof_message,
        BIGNUM* challenge) const;

    void AppendPoint(
        std::string& transcript,
        const EC_GROUP* group,
        const EC_POINT* point) const;

    void AppendScalar(
        std::string& transcript,
        const BIGNUM* scalar) const;

    bool IsValidPublicInstance(
        const CommitmentKey& commitment_key,
        const PublicInstance& public_instance) const;

    const ElGamalEnc& elgamal_;
    ElGamalCommitment commitment_scheme_;
    BN_CTX* bn_ctx_;
};

#endif // SAME_SCALAR_ARGUMENT_H
