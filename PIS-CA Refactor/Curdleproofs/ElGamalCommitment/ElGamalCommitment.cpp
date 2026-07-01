#include "ElGamalCommitment.h"

#include <stdexcept>
#include <utility>

namespace
{
EC_POINT* DuplicatePoint(const EC_GROUP* group, const EC_POINT* point)
{
    return point == nullptr ? nullptr : EC_POINT_dup(point, group);
}

void ThrowIf(bool failed, const char* message)
{
    if (failed)
    {
        throw std::runtime_error(message);
    }
}
}

ElGamalCommitment::CommitmentKey::CommitmentKey(const CommitmentKey& other)
    : group(other.group),
      GU(DuplicatePoint(other.group, other.GU)),
      GE(DuplicatePoint(other.group, other.GE)),
      H(DuplicatePoint(other.group, other.H))
{
}

ElGamalCommitment::CommitmentKey&
ElGamalCommitment::CommitmentKey::operator=(const CommitmentKey& other)
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT* new_GU = DuplicatePoint(other.group, other.GU);
    EC_POINT* new_GE = DuplicatePoint(other.group, other.GE);
    EC_POINT* new_H = DuplicatePoint(other.group, other.H);
    EC_POINT_free(GU);
    EC_POINT_free(GE);
    EC_POINT_free(H);
    group = other.group;
    GU = new_GU;
    GE = new_GE;
    H = new_H;
    return *this;
}

ElGamalCommitment::CommitmentKey::CommitmentKey(
    CommitmentKey&& other) noexcept
    : group(other.group), GU(other.GU), GE(other.GE), H(other.H)
{
    other.group = nullptr;
    other.GU = nullptr;
    other.GE = nullptr;
    other.H = nullptr;
}

ElGamalCommitment::CommitmentKey&
ElGamalCommitment::CommitmentKey::operator=(CommitmentKey&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT_free(GU);
    EC_POINT_free(GE);
    EC_POINT_free(H);
    group = other.group;
    GU = other.GU;
    GE = other.GE;
    H = other.H;
    other.group = nullptr;
    other.GU = nullptr;
    other.GE = nullptr;
    other.H = nullptr;
    return *this;
}

ElGamalCommitment::CommitmentKey::~CommitmentKey()
{
    EC_POINT_free(GU);
    EC_POINT_free(GE);
    EC_POINT_free(H);
}

ElGamalCommitment::Commitment::Commitment(const Commitment& other)
    : group(other.group),
      first(DuplicatePoint(other.group, other.first)),
      second(DuplicatePoint(other.group, other.second))
{
}

ElGamalCommitment::Commitment& ElGamalCommitment::Commitment::operator=(
    const Commitment& other)
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT* new_first = DuplicatePoint(other.group, other.first);
    EC_POINT* new_second = DuplicatePoint(other.group, other.second);
    EC_POINT_free(first);
    EC_POINT_free(second);
    group = other.group;
    first = new_first;
    second = new_second;
    return *this;
}

ElGamalCommitment::Commitment::Commitment(Commitment&& other) noexcept
    : group(other.group), first(other.first), second(other.second)
{
    other.group = nullptr;
    other.first = nullptr;
    other.second = nullptr;
}

ElGamalCommitment::Commitment& ElGamalCommitment::Commitment::operator=(
    Commitment&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT_free(first);
    EC_POINT_free(second);
    group = other.group;
    first = other.first;
    second = other.second;
    other.group = nullptr;
    other.first = nullptr;
    other.second = nullptr;
    return *this;
}

ElGamalCommitment::Commitment::~Commitment()
{
    EC_POINT_free(first);
    EC_POINT_free(second);
}

ElGamalCommitment::ElGamalCommitment(const ElGamalEnc& elgamal)
    : elgamal_(elgamal), bn_ctx_(BN_CTX_new())
{
    ThrowIf(bn_ctx_ == nullptr, "ElGamalCommitment BN_CTX allocation failed");
}

ElGamalCommitment::~ElGamalCommitment()
{
    BN_CTX_free(bn_ctx_);
}

void ElGamalCommitment::Setup(CommitmentKey& commitment_key) const
{
    EC_POINT_free(commitment_key.GU);
    EC_POINT_free(commitment_key.GE);
    EC_POINT_free(commitment_key.H);
    commitment_key.group = elgamal_.Group();
    commitment_key.GU = EC_POINT_new(commitment_key.group);
    commitment_key.GE = EC_POINT_new(commitment_key.group);
    commitment_key.H = EC_POINT_new(commitment_key.group);
    ThrowIf(
        commitment_key.GU == nullptr ||
            commitment_key.GE == nullptr ||
            commitment_key.H == nullptr,
        "ElGamalCommitment commitment key allocation failed");

    elgamal_.GenerateRandomGroupElement(commitment_key.GU);
    elgamal_.GenerateRandomGroupElement(commitment_key.GE);
    elgamal_.GenerateRandomGroupElement(commitment_key.H);
}

void ElGamalCommitment::Commit(
    const CommitmentKey& commitment_key,
    const EC_POINT* commitment_generator,
    const EC_POINT* element,
    BIGNUM* randomness,
    Commitment& commitment) const
{
    ThrowIf(
        randomness == nullptr,
        "ElGamalCommitment randomness is not initialized");

    elgamal_.GenerateRandomScalar(randomness);
    CommitWithRandomness(
        commitment_key,
        commitment_generator,
        element,
        randomness,
        commitment);
}

void ElGamalCommitment::CommitWithRandomness(
    const CommitmentKey& commitment_key,
    const EC_POINT* commitment_generator,
    const EC_POINT* element,
    const BIGNUM* randomness,
    Commitment& commitment) const
{
    ThrowIf(
        !IsValidCommitmentKey(commitment_key) ||
            commitment_generator == nullptr ||
            element == nullptr ||
            randomness == nullptr ||
            EC_POINT_is_on_curve(
                commitment_key.group,
                commitment_generator,
                bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(commitment_key.group, element, bn_ctx_) != 1,
        "ElGamalCommitment input is not initialized");

    PrepareCommitment(commitment_key.group, commitment);

    ThrowIf(
        EC_POINT_mul(
            commitment_key.group,
            commitment.first,
            nullptr,
            commitment_generator,
            randomness,
            bn_ctx_) != 1,
        "ElGamalCommitment first component failed");

    EC_POINT* randomness_term = EC_POINT_new(commitment_key.group);
    ThrowIf(
        randomness_term == nullptr,
        "ElGamalCommitment temporary point allocation failed");

    ThrowIf(
        EC_POINT_mul(
            commitment_key.group,
            randomness_term,
            nullptr,
            commitment_key.H,
            randomness,
            bn_ctx_) != 1 ||
            EC_POINT_add(
                commitment_key.group,
                commitment.second,
                element,
                randomness_term,
                bn_ctx_) != 1,
        "ElGamalCommitment second component failed");

    EC_POINT_free(randomness_term);
}

void ElGamalCommitment::Add(
    const Commitment& left,
    const Commitment& right,
    Commitment& result) const
{
    ThrowIf(
        left.group == nullptr ||
            right.group != left.group ||
            left.first == nullptr ||
            left.second == nullptr ||
            right.first == nullptr ||
            right.second == nullptr,
        "ElGamalCommitment add input is not initialized");

    PrepareCommitment(left.group, result);
    ThrowIf(
        EC_POINT_add(
            left.group,
            result.first,
            left.first,
            right.first,
            bn_ctx_) != 1 ||
            EC_POINT_add(
                left.group,
                result.second,
                left.second,
                right.second,
                bn_ctx_) != 1,
        "ElGamalCommitment homomorphic add failed");
}

bool ElGamalCommitment::IsValidCommitmentKey(
    const CommitmentKey& commitment_key) const
{
    return commitment_key.group == elgamal_.Group() &&
        commitment_key.GU != nullptr &&
        commitment_key.GE != nullptr &&
        commitment_key.H != nullptr &&
        EC_POINT_is_on_curve(commitment_key.group, commitment_key.GU, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(commitment_key.group, commitment_key.GE, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(commitment_key.group, commitment_key.H, bn_ctx_) == 1 &&
        EC_POINT_is_at_infinity(commitment_key.group, commitment_key.GU) != 1 &&
        EC_POINT_is_at_infinity(commitment_key.group, commitment_key.GE) != 1 &&
        EC_POINT_is_at_infinity(commitment_key.group, commitment_key.H) != 1;
}

bool ElGamalCommitment::IsValidCommitment(
    const Commitment& commitment) const
{
    return commitment.group == elgamal_.Group() &&
        commitment.first != nullptr &&
        commitment.second != nullptr &&
        EC_POINT_is_on_curve(commitment.group, commitment.first, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(commitment.group, commitment.second, bn_ctx_) == 1;
}

void ElGamalCommitment::PrepareCommitment(
    const EC_GROUP* group,
    Commitment& commitment) const
{
    ThrowIf(group == nullptr, "ElGamalCommitment group is not initialized");

    if (commitment.group != group)
    {
        EC_POINT_free(commitment.first);
        EC_POINT_free(commitment.second);
        commitment.group = group;
        commitment.first = nullptr;
        commitment.second = nullptr;
    }

    if (commitment.first == nullptr)
    {
        commitment.first = EC_POINT_new(commitment.group);
    }
    if (commitment.second == nullptr)
    {
        commitment.second = EC_POINT_new(commitment.group);
    }

    ThrowIf(
        commitment.first == nullptr || commitment.second == nullptr,
        "ElGamalCommitment commitment allocation failed");
}
