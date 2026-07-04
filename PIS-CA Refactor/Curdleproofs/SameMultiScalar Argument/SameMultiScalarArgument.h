#pragma once

#ifndef SAME_MULTI_SCALAR_ARGUMENT_H
#define SAME_MULTI_SCALAR_ARGUMENT_H

#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../ElGamalCommitment/ElGamalCommitment.h"
#include "../../ElGamal/ElGamalEnc.h"

class SameMultiScalarArgument
{
public:
    using CommitmentKey = ElGamalCommitment::CommitmentKey;
    using ScalarCommitment = ElGamalEnc::Commitment;
    using GroupCommitment = ElGamalCommitment::Commitment;
    using Ciphertext = ElGamalEnc::Ciphertext;

    struct PublicInstance
    {
        const EC_GROUP* group = nullptr;
        std::vector<Ciphertext> ciphertexts;
        std::vector<EC_POINT*> g;
        std::vector<EC_POINT*> h;
        std::vector<EC_POINT*> G;
        std::vector<EC_POINT*> U;
        std::vector<EC_POINT*> E;
        EC_POINT* GU = nullptr;
        EC_POINT* GE = nullptr;
        EC_POINT* H = nullptr;
        EC_POINT* h1 = nullptr;
        EC_POINT* h2 = nullptr;
        EC_POINT* h3 = nullptr;
        EC_POINT* A_m = nullptr;
        EC_POINT* cm_um = nullptr;
        EC_POINT* cm_em = nullptr;

        PublicInstance() = default;
        PublicInstance(const PublicInstance& other);
        PublicInstance& operator=(const PublicInstance& other);
        PublicInstance(PublicInstance&& other) noexcept;
        PublicInstance& operator=(PublicInstance&& other) noexcept;
        ~PublicInstance();
    };

    struct Witness
    {
        std::vector<BIGNUM*> x;
        std::vector<BIGNUM*> sigma_a;
        std::vector<BIGNUM*> r_A;
        BIGNUM* r_u = nullptr;
        BIGNUM* r_e = nullptr;
        std::vector<BIGNUM*> r_L_randomness;
        std::vector<BIGNUM*> r_R_randomness;
        BIGNUM* x_randomness = nullptr;
        BIGNUM* r_h_randomness = nullptr;

        Witness() = default;
        Witness(const Witness& other);
        Witness& operator=(const Witness& other);
        Witness(Witness&& other) noexcept;
        Witness& operator=(Witness&& other) noexcept;
        ~Witness();
    };

    struct ProofMessage
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* B_A = nullptr;
        EC_POINT* B_U = nullptr;
        EC_POINT* B_E = nullptr;
        std::vector<EC_POINT*> L_A;
        std::vector<EC_POINT*> R_A;
        std::vector<EC_POINT*> L_U;
        std::vector<EC_POINT*> R_U;
        std::vector<EC_POINT*> L_E;
        std::vector<EC_POINT*> R_E;
        BIGNUM* x = nullptr;
        BIGNUM* r_h = nullptr;

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

    explicit SameMultiScalarArgument(const ElGamalEnc& elgamal);
    SameMultiScalarArgument(const SameMultiScalarArgument&) = delete;
    SameMultiScalarArgument& operator=(const SameMultiScalarArgument&) = delete;
    ~SameMultiScalarArgument();

    void InitializePublicInstance(
        const CommitmentKey& commitment_key,
        const ScalarCommitment& A,
        const GroupCommitment& cm_u,
        const GroupCommitment& cm_e,
        const std::vector<Ciphertext>& ciphertexts,
        const std::vector<EC_POINT*>& g,
        const std::vector<EC_POINT*>& h,
        const std::vector<BIGNUM*>& sigma_a,
        const std::vector<BIGNUM*>& r_A,
        const BIGNUM* r_u,
        const BIGNUM* r_e,
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
        const EC_GROUP* group,
        const std::string& label,
        const std::vector<const EC_POINT*>& points,
        BIGNUM* challenge) const;
    void AppendPoint(
        std::string& transcript,
        const EC_GROUP* group,
        const EC_POINT* point) const;
    bool IsValidPublicInstance(
        const CommitmentKey& commitment_key,
        const PublicInstance& public_instance) const;
    bool IsPowerOfTwo(std::size_t value) const;

    const ElGamalEnc& elgamal_;
    ElGamalCommitment commitment_scheme_;
    BN_CTX* bn_ctx_;
};

#endif // SAME_MULTI_SCALAR_ARGUMENT_H
