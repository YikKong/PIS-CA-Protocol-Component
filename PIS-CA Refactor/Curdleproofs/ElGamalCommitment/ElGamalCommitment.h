#pragma once

#ifndef ELGAMAL_COMMITMENT_H
#define ELGAMAL_COMMITMENT_H

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../../ElGamal/ElGamalEnc.h"

class ElGamalCommitment
{
public:
    struct CommitmentKey
    {
        const EC_GROUP* group = nullptr;
        EC_POINT* GU = nullptr;
        EC_POINT* GE = nullptr;
        EC_POINT* H = nullptr;

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
        EC_POINT* first = nullptr;
        EC_POINT* second = nullptr;

        Commitment() = default;
        Commitment(const Commitment& other);
        Commitment& operator=(const Commitment& other);
        Commitment(Commitment&& other) noexcept;
        Commitment& operator=(Commitment&& other) noexcept;
        ~Commitment();
    };

    explicit ElGamalCommitment(const ElGamalEnc& elgamal);
    ElGamalCommitment(const ElGamalCommitment&) = delete;
    ElGamalCommitment& operator=(const ElGamalCommitment&) = delete;
    ~ElGamalCommitment();

    void Setup(CommitmentKey& commitment_key) const;

    // GroupCommit((G, H); T; r_T) = (r_T * G, T + r_T * H).
    void Commit(
        const CommitmentKey& commitment_key,
        const EC_POINT* commitment_generator,
        const EC_POINT* element,
        BIGNUM* randomness,
        Commitment& commitment) const;

    void CommitWithRandomness(
        const CommitmentKey& commitment_key,
        const EC_POINT* commitment_generator,
        const EC_POINT* element,
        const BIGNUM* randomness,
        Commitment& commitment) const;

    // Homomorphism:
    // Commit(A; r_A) + Commit(B; r_B) = Commit(A + B; r_A + r_B).
    void Add(
        const Commitment& left,
        const Commitment& right,
        Commitment& result) const;

    bool IsValidCommitmentKey(const CommitmentKey& commitment_key) const;
    bool IsValidCommitment(const Commitment& commitment) const;

private:
    void PrepareCommitment(
        const EC_GROUP* group,
        Commitment& commitment) const;

    const ElGamalEnc& elgamal_;
    BN_CTX* bn_ctx_;
};

#endif // ELGAMAL_COMMITMENT_H
