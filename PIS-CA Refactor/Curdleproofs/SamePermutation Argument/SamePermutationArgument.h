#pragma once

#ifndef SAME_PERMUTATION_ARGUMENT_H
#define SAME_PERMUTATION_ARGUMENT_H

#include <cstddef>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../../ElGamal/ElGamalEnc.h"

class SamePermutationArgument
{
public:
    using Commitment = ElGamalEnc::Commitment;

    struct GrandProductPublicInstance
    {
        const EC_GROUP* group = nullptr;
        std::vector<EC_POINT*> g;
        EC_POINT* h = nullptr;
        Commitment B;
        BIGNUM* p = nullptr;

        GrandProductPublicInstance() = default;
        GrandProductPublicInstance(const GrandProductPublicInstance& other);
        GrandProductPublicInstance& operator=(const GrandProductPublicInstance& other);
        GrandProductPublicInstance(GrandProductPublicInstance&& other) noexcept;
        GrandProductPublicInstance& operator=(GrandProductPublicInstance&& other) noexcept;
        ~GrandProductPublicInstance();
    };

    struct GrandProductWitness
    {
        std::vector<BIGNUM*> b;
        BIGNUM* r_B = nullptr;

        GrandProductWitness() = default;
        GrandProductWitness(const GrandProductWitness& other);
        GrandProductWitness& operator=(const GrandProductWitness& other);
        GrandProductWitness(GrandProductWitness&& other) noexcept;
        GrandProductWitness& operator=(GrandProductWitness&& other) noexcept;
        ~GrandProductWitness();
    };

    struct InnerProductPublicInstance
    {
        const EC_GROUP* group = nullptr;
        std::vector<EC_POINT*> G;
        std::vector<EC_POINT*> G_prime;
        EC_POINT* H = nullptr;
        EC_POINT* h = nullptr;
        Commitment C;
        Commitment D;
        BIGNUM* z = nullptr;

        InnerProductPublicInstance() = default;
        InnerProductPublicInstance(const InnerProductPublicInstance& other);
        InnerProductPublicInstance& operator=(const InnerProductPublicInstance& other);
        InnerProductPublicInstance(InnerProductPublicInstance&& other) noexcept;
        InnerProductPublicInstance& operator=(InnerProductPublicInstance&& other) noexcept;
        ~InnerProductPublicInstance();
    };

    struct InnerProductWitness
    {
        std::vector<BIGNUM*> c;
        std::vector<BIGNUM*> d;

        InnerProductWitness() = default;
        InnerProductWitness(const InnerProductWitness& other);
        InnerProductWitness& operator=(const InnerProductWitness& other);
        InnerProductWitness(InnerProductWitness&& other) noexcept;
        InnerProductWitness& operator=(InnerProductWitness&& other) noexcept;
        ~InnerProductWitness();
    };

    struct GrandProductProofMessage
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* B = nullptr;
        EC_POINT* C = nullptr;
        BIGNUM* r_p = nullptr;

        GrandProductProofMessage() = default;
        GrandProductProofMessage(const GrandProductProofMessage& other);
        GrandProductProofMessage& operator=(const GrandProductProofMessage& other);
        GrandProductProofMessage(GrandProductProofMessage&& other) noexcept;
        GrandProductProofMessage& operator=(GrandProductProofMessage&& other) noexcept;
        ~GrandProductProofMessage();
    };

    struct InnerProductProofMessage
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* A = nullptr;
        EC_POINT* B = nullptr;
        std::vector<EC_POINT*> L;
        std::vector<EC_POINT*> R;
        BIGNUM* c = nullptr;
        BIGNUM* d = nullptr;
        BIGNUM* r_h = nullptr;

        InnerProductProofMessage();
        InnerProductProofMessage(const InnerProductProofMessage& other);
        InnerProductProofMessage& operator=(const InnerProductProofMessage& other);
        InnerProductProofMessage(InnerProductProofMessage&& other) noexcept;
        InnerProductProofMessage& operator=(InnerProductProofMessage&& other) noexcept;
        ~InnerProductProofMessage();
    };

    struct PublicInstance
    {
        const EC_GROUP* group = nullptr;
        std::vector<EC_POINT*> g;
        EC_POINT* h = nullptr;
        std::vector<BIGNUM*> a;
        std::vector<BIGNUM*> n;
        Commitment A;
        Commitment M;
        GrandProductPublicInstance grand_product;
        InnerProductPublicInstance inner_product;

        PublicInstance() = default;
        PublicInstance(const PublicInstance& other);
        PublicInstance& operator=(const PublicInstance& other);
        PublicInstance(PublicInstance&& other) noexcept;
        PublicInstance& operator=(PublicInstance&& other) noexcept;
        ~PublicInstance();
    };

    struct Witness
    {
        std::vector<std::size_t> permutation;
        std::vector<BIGNUM*> sigma_a;
        std::vector<BIGNUM*> sigma_n;
        BIGNUM* r_A = nullptr;
        BIGNUM* r_M = nullptr;
        GrandProductWitness grand_product;
        InnerProductWitness inner_product;

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
        GrandProductProofMessage grand_product;
        InnerProductProofMessage inner_product;

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

    explicit SamePermutationArgument(const ElGamalEnc& elgamal);
    SamePermutationArgument(const SamePermutationArgument&) = delete;
    SamePermutationArgument& operator=(const SamePermutationArgument&) = delete;
    ~SamePermutationArgument();

    void InitializeSamePermutationProof(
        const std::vector<BIGNUM*>& a,
        const std::vector<std::size_t>& permutation,
        const BIGNUM* r_A,
        const BIGNUM* r_M,
        PublicInstance& public_instance,
        Witness& witness) const;

    void CreateGrandProductProof(
        const GrandProductPublicInstance& public_instance,
        const GrandProductWitness& witness,
        InnerProductPublicInstance& inner_product_public_instance,
        InnerProductWitness& inner_product_witness,
        GrandProductProofMessage& proof_message,
        InnerProductProofMessage& inner_product_proof_message) const;

    bool VerifyGrandProductProof(
        const GrandProductPublicInstance& public_instance,
        const InnerProductPublicInstance& inner_product_public_instance,
        const GrandProductProofMessage& proof_message,
        const InnerProductProofMessage& inner_product_proof_message) const;

    void CreateInnerProductProof(
        const InnerProductPublicInstance& public_instance,
        const InnerProductWitness& witness,
        InnerProductProofMessage& proof_message) const;

    bool VerifyInnerProductProof(
        const InnerProductPublicInstance& public_instance,
        const InnerProductProofMessage& proof_message) const;

    void CreateSamePermutationProof(
        const PublicInstance& public_instance,
        const Witness& witness,
        Proof& proof) const;

    bool VerifySamePermutationProof(
        const PublicInstance& public_instance,
        const ProofMessage& proof_message) const;

    bool VerifySamePermutationProof(const Proof& proof) const;

private:
    void GenerateSamePermutationChallenges(
        const PublicInstance& public_instance,
        BIGNUM* alpha,
        BIGNUM* beta) const;
    void GenerateGrandProductAlpha(
        const GrandProductPublicInstance& public_instance,
        BIGNUM* alpha) const;
    void GenerateGrandProductBeta(
        const GrandProductProofMessage& proof_message,
        BIGNUM* beta) const;
    void GenerateInnerProductChallenges(
        const InnerProductPublicInstance& public_instance,
        BIGNUM* beta,
        BIGNUM* e) const;
    void GenerateInnerProductRoundChallenge(
        const EC_POINT* L,
        const EC_POINT* R,
        BIGNUM* gamma) const;
    void GenerateInnerProductAlpha(
        const InnerProductPublicInstance& public_instance,
        const InnerProductProofMessage& proof_message,
        BIGNUM* alpha) const;
    void AppendPoint(std::string& transcript, const EC_POINT* point) const;
    void AppendScalar(std::string& transcript, const BIGNUM* scalar) const;
    bool IsValidPublicInstance(const PublicInstance& public_instance) const;
    bool IsValidGrandProductPublicInstance(
        const GrandProductPublicInstance& public_instance) const;
    bool HasMatchingGrandProductGenerators(
        const PublicInstance& public_instance) const;
    bool IsValidPermutation(
        const std::vector<std::size_t>& permutation,
        std::size_t size) const;
    bool VectorCommit(
        const std::vector<EC_POINT*>& g,
        const EC_POINT* h,
        const std::vector<BIGNUM*>& values,
        const BIGNUM* randomness,
        EC_POINT* result) const;

    const ElGamalEnc& elgamal_;
    BN_CTX* bn_ctx_;
};

#endif // SAME_PERMUTATION_ARGUMENT_H
