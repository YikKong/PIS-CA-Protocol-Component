#include "SameScalarArgument.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

#include <openssl/sha.h>

namespace
{
EC_POINT* DuplicatePoint(const EC_GROUP* group, const EC_POINT* point)
{
    return point == nullptr ? nullptr : EC_POINT_dup(point, group);
}

BIGNUM* DuplicateBN(const BIGNUM* value)
{
    return value == nullptr ? nullptr : BN_dup(value);
}

void ThrowIf(bool failed, const char* message)
{
    if (failed)
    {
        throw std::runtime_error(message);
    }
}

void AllocateBNIfNull(BIGNUM*& value, const char* message)
{
    if (value == nullptr)
    {
        value = BN_new();
        ThrowIf(value == nullptr, message);
    }
}

std::vector<BIGNUM*> DuplicateBNVector(const std::vector<BIGNUM*>& values)
{
    std::vector<BIGNUM*> duplicates;
    duplicates.reserve(values.size());
    try
    {
        for (const BIGNUM* value : values)
        {
            BIGNUM* duplicate = DuplicateBN(value);
            ThrowIf(
                value != nullptr && duplicate == nullptr,
                "SameScalar public instance scalar copy failed");
            duplicates.emplace_back(duplicate);
        }
    }
    catch (...)
    {
        for (BIGNUM* duplicate : duplicates)
        {
            BN_clear_free(duplicate);
        }
        throw;
    }
    return duplicates;
}

void FreeBNVector(std::vector<BIGNUM*>& values)
{
    for (BIGNUM* value : values)
    {
        BN_clear_free(value);
    }
    values.clear();
}
}

SameScalarArgument::PublicInstance::PublicInstance(
    const PublicInstance& other)
    : group(other.group),
      ciphertexts(other.ciphertexts),
      a(DuplicateBNVector(other.a)),
      u(DuplicatePoint(other.group, other.u)),
      e(DuplicatePoint(other.group, other.e)),
      u_a_sum(DuplicatePoint(other.group, other.u_a_sum)),
      e_a_sum(DuplicatePoint(other.group, other.e_a_sum)),
      cm_u(other.cm_u),
      cm_e(other.cm_e)
{
}

SameScalarArgument::PublicInstance&
SameScalarArgument::PublicInstance::operator=(const PublicInstance& other)
{
    if (this == &other)
    {
        return *this;
    }

    std::vector<BIGNUM*> new_a = DuplicateBNVector(other.a);
    EC_POINT* new_u = DuplicatePoint(other.group, other.u);
    EC_POINT* new_e = DuplicatePoint(other.group, other.e);
    EC_POINT* new_u_a_sum = DuplicatePoint(other.group, other.u_a_sum);
    EC_POINT* new_e_a_sum = DuplicatePoint(other.group, other.e_a_sum);
    EC_POINT_free(u);
    EC_POINT_free(e);
    EC_POINT_free(u_a_sum);
    EC_POINT_free(e_a_sum);
    FreeBNVector(a);
    group = other.group;
    ciphertexts = other.ciphertexts;
    a = std::move(new_a);
    u = new_u;
    e = new_e;
    u_a_sum = new_u_a_sum;
    e_a_sum = new_e_a_sum;
    cm_u = other.cm_u;
    cm_e = other.cm_e;
    return *this;
}

SameScalarArgument::PublicInstance::PublicInstance(
    PublicInstance&& other) noexcept
    : group(other.group),
      ciphertexts(std::move(other.ciphertexts)),
      a(std::move(other.a)),
      u(other.u),
      e(other.e),
      u_a_sum(other.u_a_sum),
      e_a_sum(other.e_a_sum),
      cm_u(std::move(other.cm_u)),
      cm_e(std::move(other.cm_e))
{
    other.group = nullptr;
    other.a.clear();
    other.u = nullptr;
    other.e = nullptr;
    other.u_a_sum = nullptr;
    other.e_a_sum = nullptr;
}

SameScalarArgument::PublicInstance&
SameScalarArgument::PublicInstance::operator=(
    PublicInstance&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT_free(u);
    EC_POINT_free(e);
    EC_POINT_free(u_a_sum);
    EC_POINT_free(e_a_sum);
    FreeBNVector(a);
    group = other.group;
    ciphertexts = std::move(other.ciphertexts);
    a = std::move(other.a);
    u = other.u;
    e = other.e;
    u_a_sum = other.u_a_sum;
    e_a_sum = other.e_a_sum;
    cm_u = std::move(other.cm_u);
    cm_e = std::move(other.cm_e);
    other.group = nullptr;
    other.a.clear();
    other.u = nullptr;
    other.e = nullptr;
    other.u_a_sum = nullptr;
    other.e_a_sum = nullptr;
    return *this;
}

SameScalarArgument::PublicInstance::~PublicInstance()
{
    EC_POINT_free(u);
    EC_POINT_free(e);
    EC_POINT_free(u_a_sum);
    EC_POINT_free(e_a_sum);
    FreeBNVector(a);
}

SameScalarArgument::Witness::Witness()
    : k(BN_new()),
      r_u(BN_new()),
      r_e(BN_new()),
      k_randomness(BN_new()),
      r_u_randomness(BN_new()),
      r_e_randomness(BN_new())
{
    ThrowIf(
        k == nullptr ||
            r_u == nullptr ||
            r_e == nullptr ||
            k_randomness == nullptr ||
            r_u_randomness == nullptr ||
            r_e_randomness == nullptr,
        "SameScalar witness allocation failed");
}

SameScalarArgument::Witness::Witness(const Witness& other)
    : k(DuplicateBN(other.k)),
      r_u(DuplicateBN(other.r_u)),
      r_e(DuplicateBN(other.r_e)),
      k_randomness(DuplicateBN(other.k_randomness)),
      r_u_randomness(DuplicateBN(other.r_u_randomness)),
      r_e_randomness(DuplicateBN(other.r_e_randomness))
{
    ThrowIf(other.k != nullptr && k == nullptr, "SameScalar witness k copy failed");
    ThrowIf(other.r_u != nullptr && r_u == nullptr, "SameScalar witness r_u copy failed");
    ThrowIf(other.r_e != nullptr && r_e == nullptr, "SameScalar witness r_e copy failed");
    ThrowIf(
        other.k_randomness != nullptr && k_randomness == nullptr,
        "SameScalar witness k randomness copy failed");
    ThrowIf(
        other.r_u_randomness != nullptr && r_u_randomness == nullptr,
        "SameScalar witness r_u randomness copy failed");
    ThrowIf(
        other.r_e_randomness != nullptr && r_e_randomness == nullptr,
        "SameScalar witness r_e randomness copy failed");
}

SameScalarArgument::Witness& SameScalarArgument::Witness::operator=(
    const Witness& other)
{
    if (this == &other)
    {
        return *this;
    }

    BIGNUM* new_k = DuplicateBN(other.k);
    BIGNUM* new_r_u = DuplicateBN(other.r_u);
    BIGNUM* new_r_e = DuplicateBN(other.r_e);
    BIGNUM* new_k_randomness = DuplicateBN(other.k_randomness);
    BIGNUM* new_r_u_randomness = DuplicateBN(other.r_u_randomness);
    BIGNUM* new_r_e_randomness = DuplicateBN(other.r_e_randomness);
    ThrowIf(other.k != nullptr && new_k == nullptr, "SameScalar witness k copy failed");
    ThrowIf(other.r_u != nullptr && new_r_u == nullptr, "SameScalar witness r_u copy failed");
    ThrowIf(other.r_e != nullptr && new_r_e == nullptr, "SameScalar witness r_e copy failed");
    ThrowIf(
        other.k_randomness != nullptr && new_k_randomness == nullptr,
        "SameScalar witness k randomness copy failed");
    ThrowIf(
        other.r_u_randomness != nullptr && new_r_u_randomness == nullptr,
        "SameScalar witness r_u randomness copy failed");
    ThrowIf(
        other.r_e_randomness != nullptr && new_r_e_randomness == nullptr,
        "SameScalar witness r_e randomness copy failed");
    BN_clear_free(k);
    BN_clear_free(r_u);
    BN_clear_free(r_e);
    BN_clear_free(k_randomness);
    BN_clear_free(r_u_randomness);
    BN_clear_free(r_e_randomness);
    k = new_k;
    r_u = new_r_u;
    r_e = new_r_e;
    k_randomness = new_k_randomness;
    r_u_randomness = new_r_u_randomness;
    r_e_randomness = new_r_e_randomness;
    return *this;
}

SameScalarArgument::Witness::Witness(Witness&& other) noexcept
    : k(other.k),
      r_u(other.r_u),
      r_e(other.r_e),
      k_randomness(other.k_randomness),
      r_u_randomness(other.r_u_randomness),
      r_e_randomness(other.r_e_randomness)
{
    other.k = nullptr;
    other.r_u = nullptr;
    other.r_e = nullptr;
    other.k_randomness = nullptr;
    other.r_u_randomness = nullptr;
    other.r_e_randomness = nullptr;
}

SameScalarArgument::Witness& SameScalarArgument::Witness::operator=(
    Witness&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    BN_clear_free(k);
    BN_clear_free(r_u);
    BN_clear_free(r_e);
    BN_clear_free(k_randomness);
    BN_clear_free(r_u_randomness);
    BN_clear_free(r_e_randomness);
    k = other.k;
    r_u = other.r_u;
    r_e = other.r_e;
    k_randomness = other.k_randomness;
    r_u_randomness = other.r_u_randomness;
    r_e_randomness = other.r_e_randomness;
    other.k = nullptr;
    other.r_u = nullptr;
    other.r_e = nullptr;
    other.k_randomness = nullptr;
    other.r_u_randomness = nullptr;
    other.r_e_randomness = nullptr;
    return *this;
}

SameScalarArgument::Witness::~Witness()
{
    BN_clear_free(k);
    BN_clear_free(r_u);
    BN_clear_free(r_e);
    BN_clear_free(k_randomness);
    BN_clear_free(r_u_randomness);
    BN_clear_free(r_e_randomness);
}

SameScalarArgument::ProofMessage::ProofMessage()
    : k_response(BN_new()),
      r_u_response(BN_new()),
      r_e_response(BN_new())
{
    ThrowIf(
        k_response == nullptr ||
            r_u_response == nullptr ||
            r_e_response == nullptr,
        "SameScalar proof response allocation failed");
}

SameScalarArgument::ProofMessage::ProofMessage(const ProofMessage& other)
    : random_u_commitment(other.random_u_commitment),
      random_e_commitment(other.random_e_commitment),
      k_response(DuplicateBN(other.k_response)),
      r_u_response(DuplicateBN(other.r_u_response)),
      r_e_response(DuplicateBN(other.r_e_response))
{
    ThrowIf(
        other.k_response != nullptr && k_response == nullptr,
        "SameScalar proof k response copy failed");
    ThrowIf(
        other.r_u_response != nullptr && r_u_response == nullptr,
        "SameScalar proof u-randomness response copy failed");
    ThrowIf(
        other.r_e_response != nullptr && r_e_response == nullptr,
        "SameScalar proof e-randomness response copy failed");
}

SameScalarArgument::ProofMessage& SameScalarArgument::ProofMessage::operator=(
    const ProofMessage& other)
{
    if (this == &other)
    {
        return *this;
    }

    BIGNUM* new_k_response = DuplicateBN(other.k_response);
    BIGNUM* new_r_u_response = DuplicateBN(other.r_u_response);
    BIGNUM* new_r_e_response = DuplicateBN(other.r_e_response);
    ThrowIf(
        other.k_response != nullptr && new_k_response == nullptr,
        "SameScalar proof k response copy failed");
    ThrowIf(
        other.r_u_response != nullptr && new_r_u_response == nullptr,
        "SameScalar proof u-randomness response copy failed");
    ThrowIf(
        other.r_e_response != nullptr && new_r_e_response == nullptr,
        "SameScalar proof e-randomness response copy failed");

    random_u_commitment = other.random_u_commitment;
    random_e_commitment = other.random_e_commitment;
    BN_clear_free(k_response);
    BN_clear_free(r_u_response);
    BN_clear_free(r_e_response);
    k_response = new_k_response;
    r_u_response = new_r_u_response;
    r_e_response = new_r_e_response;
    return *this;
}

SameScalarArgument::ProofMessage::ProofMessage(ProofMessage&& other) noexcept
    : random_u_commitment(std::move(other.random_u_commitment)),
      random_e_commitment(std::move(other.random_e_commitment)),
      k_response(other.k_response),
      r_u_response(other.r_u_response),
      r_e_response(other.r_e_response)
{
    other.k_response = nullptr;
    other.r_u_response = nullptr;
    other.r_e_response = nullptr;
}

SameScalarArgument::ProofMessage& SameScalarArgument::ProofMessage::operator=(
    ProofMessage&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    random_u_commitment = std::move(other.random_u_commitment);
    random_e_commitment = std::move(other.random_e_commitment);
    BN_clear_free(k_response);
    BN_clear_free(r_u_response);
    BN_clear_free(r_e_response);
    k_response = other.k_response;
    r_u_response = other.r_u_response;
    r_e_response = other.r_e_response;
    other.k_response = nullptr;
    other.r_u_response = nullptr;
    other.r_e_response = nullptr;
    return *this;
}

SameScalarArgument::ProofMessage::~ProofMessage()
{
    BN_clear_free(k_response);
    BN_clear_free(r_u_response);
    BN_clear_free(r_e_response);
}

SameScalarArgument::SameScalarArgument(const ElGamalEnc& elgamal)
    : elgamal_(elgamal), commitment_scheme_(elgamal), bn_ctx_(BN_CTX_new())
{
    ThrowIf(bn_ctx_ == nullptr, "SameScalar BN_CTX allocation failed");
}

SameScalarArgument::~SameScalarArgument()
{
    BN_CTX_free(bn_ctx_);
}

void SameScalarArgument::InitializePublicInstance(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<BIGNUM*>& a,
    const BIGNUM* k,
    PublicInstance& public_instance,
    Witness& witness) const
{
    const EC_GROUP* group = elgamal_.Group();
    ThrowIf(
        !elgamal_.IsValidPublicKey(public_key) ||
            !commitment_scheme_.IsValidCommitmentKey(commitment_key) ||
            ciphertexts.empty() ||
            ciphertexts.size() != a.size() ||
            k == nullptr,
        "SameScalar public instance aggregate input size mismatch");

    for (std::size_t i = 0; i < ciphertexts.size(); ++i)
    {
        ThrowIf(
            a[i] == nullptr ||
                ciphertexts[i].group != group ||
                !elgamal_.IsValidCiphertext(ciphertexts[i]),
            "SameScalar public instance aggregate input is invalid");
    }

    std::vector<BIGNUM*> new_a = DuplicateBNVector(a);
    BIGNUM* new_k = DuplicateBN(k);
    BIGNUM* new_r_u = BN_new();
    BIGNUM* new_r_e = BN_new();
    BIGNUM* sum_a = BN_new();
    EC_POINT* new_u = EC_POINT_new(group);
    EC_POINT* new_e = EC_POINT_new(group);
    EC_POINT* new_u_a_sum = EC_POINT_new(group);
    EC_POINT* new_e_a_sum = EC_POINT_new(group);
    EC_POINT* committed_u = EC_POINT_new(group);
    EC_POINT* committed_e = EC_POINT_new(group);
    EC_POINT* term = EC_POINT_new(group);
    Commitment new_cm_u;
    Commitment new_cm_e;
    bool aggregate_ok = new_k != nullptr &&
        new_r_u != nullptr &&
        new_r_e != nullptr &&
        sum_a != nullptr &&
        new_u != nullptr &&
        new_e != nullptr &&
        new_u_a_sum != nullptr &&
        new_e_a_sum != nullptr &&
        committed_u != nullptr &&
        committed_e != nullptr &&
        term != nullptr &&
        BN_set_word(sum_a, 0) == 1 &&
        EC_POINT_set_to_infinity(group, new_u) == 1 &&
        EC_POINT_set_to_infinity(group, new_e) == 1;

    for (std::size_t i = 0; aggregate_ok && i < ciphertexts.size(); ++i)
    {
        aggregate_ok =
            BN_mod_add(sum_a, sum_a, a[i], elgamal_.Order(), bn_ctx_) == 1 &&
            EC_POINT_mul(
                group,
                term,
                nullptr,
                ciphertexts[i].u,
                a[i],
                bn_ctx_) == 1 &&
            EC_POINT_add(group, new_u, new_u, term, bn_ctx_) == 1 &&
            EC_POINT_mul(
                group,
                term,
                nullptr,
                ciphertexts[i].e,
                a[i],
                bn_ctx_) == 1 &&
            EC_POINT_add(group, new_e, new_e, term, bn_ctx_) == 1;
    }

    if (aggregate_ok)
    {
        elgamal_.GenerateRandomScalar(new_r_u);
        elgamal_.GenerateRandomScalar(new_r_e);
        aggregate_ok =
            EC_POINT_mul(
                group,
                new_u_a_sum,
                nullptr,
                public_key.g,
                sum_a,
                bn_ctx_) == 1 &&
            EC_POINT_mul(
                group,
                new_e_a_sum,
                nullptr,
                public_key.pk,
                sum_a,
                bn_ctx_) == 1 &&
            EC_POINT_mul(
                group,
                committed_u,
                nullptr,
                new_u_a_sum,
                new_k,
                bn_ctx_) == 1 &&
            EC_POINT_mul(
                group,
                committed_e,
                nullptr,
                new_e_a_sum,
                new_k,
                bn_ctx_) == 1;
    }

    if (aggregate_ok)
    {
        aggregate_ok =
            EC_POINT_add(group, committed_u, new_u, committed_u, bn_ctx_) == 1 &&
            EC_POINT_add(group, committed_e, new_e, committed_e, bn_ctx_) == 1;
    }

    if (aggregate_ok)
    {
        commitment_scheme_.CommitWithRandomness(
            commitment_key,
            commitment_key.GU,
            committed_u,
            new_r_u,
            new_cm_u);
        commitment_scheme_.CommitWithRandomness(
            commitment_key,
            commitment_key.GE,
            committed_e,
            new_r_e,
            new_cm_e);
    }

    EC_POINT_free(term);
    EC_POINT_free(committed_u);
    EC_POINT_free(committed_e);
    if (!aggregate_ok)
    {
        EC_POINT_free(new_u);
        EC_POINT_free(new_e);
        EC_POINT_free(new_u_a_sum);
        EC_POINT_free(new_e_a_sum);
        BN_clear_free(new_k);
        BN_clear_free(new_r_u);
        BN_clear_free(new_r_e);
        BN_clear_free(sum_a);
        FreeBNVector(new_a);
        ThrowIf(true, "SameScalar public instance aggregate computation failed");
    }

    EC_POINT_free(public_instance.u);
    EC_POINT_free(public_instance.e);
    EC_POINT_free(public_instance.u_a_sum);
    EC_POINT_free(public_instance.e_a_sum);
    FreeBNVector(public_instance.a);
    public_instance.group = group;
    public_instance.ciphertexts = ciphertexts;
    public_instance.a = std::move(new_a);
    public_instance.u = new_u;
    public_instance.e = new_e;
    public_instance.u_a_sum = new_u_a_sum;
    public_instance.e_a_sum = new_e_a_sum;
    public_instance.cm_u = std::move(new_cm_u);
    public_instance.cm_e = std::move(new_cm_e);

    BN_clear_free(sum_a);
    BN_clear_free(witness.k);
    BN_clear_free(witness.r_u);
    BN_clear_free(witness.r_e);
    witness.k = new_k;
    witness.r_u = new_r_u;
    witness.r_e = new_r_e;
}

void SameScalarArgument::CreateProof(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance,
    const Witness& witness,
    Proof& proof) const
{
    ThrowIf(
        !commitment_scheme_.IsValidCommitmentKey(commitment_key) ||
            !IsValidPublicInstance(commitment_key, public_instance) ||
            witness.k == nullptr ||
            witness.r_u == nullptr ||
            witness.r_e == nullptr,
        "SameScalar proof input is not initialized");

    proof.public_instance = public_instance;
    proof.witness = witness;
    AllocateBNIfNull(
        proof.witness.k_randomness,
        "SameScalar witness k randomness allocation failed");
    AllocateBNIfNull(
        proof.witness.r_u_randomness,
        "SameScalar witness r_u randomness allocation failed");
    AllocateBNIfNull(
        proof.witness.r_e_randomness,
        "SameScalar witness r_e randomness allocation failed");

    BIGNUM* challenge = BN_new();
    BIGNUM* temp = BN_new();
    EC_POINT* masked_u = EC_POINT_new(commitment_key.group);
    EC_POINT* masked_e = EC_POINT_new(commitment_key.group);
    ThrowIf(
        challenge == nullptr ||
            temp == nullptr ||
            masked_u == nullptr ||
            masked_e == nullptr,
        "SameScalar proof temporary allocation failed");

    elgamal_.GenerateRandomScalar(proof.witness.k_randomness);
    elgamal_.GenerateRandomScalar(proof.witness.r_u_randomness);
    elgamal_.GenerateRandomScalar(proof.witness.r_e_randomness);

    ThrowIf(
            EC_POINT_mul(
                commitment_key.group,
                masked_u,
                nullptr,
                public_instance.u_a_sum,
            proof.witness.k_randomness,
            bn_ctx_) != 1 ||
            EC_POINT_mul(
                commitment_key.group,
                masked_e,
                nullptr,
                public_instance.e_a_sum,
                proof.witness.k_randomness,
                bn_ctx_) != 1,
        "SameScalar proof masked statement computation failed");
    ThrowIf(
        EC_POINT_add(
            commitment_key.group,
            masked_u,
            public_instance.u,
            masked_u,
            bn_ctx_) != 1 ||
            EC_POINT_add(
                commitment_key.group,
                masked_e,
                public_instance.e,
                masked_e,
                bn_ctx_) != 1,
        "SameScalar proof masked statement offset addition failed");

    commitment_scheme_.CommitWithRandomness(
        commitment_key,
        commitment_key.GU,
        masked_u,
        proof.witness.r_u_randomness,
        proof.message.random_u_commitment);
    commitment_scheme_.CommitWithRandomness(
        commitment_key,
        commitment_key.GE,
        masked_e,
        proof.witness.r_e_randomness,
        proof.message.random_e_commitment);

    GenerateChallenge(
        commitment_key,
        public_instance,
        proof.message,
        challenge);

    BN_mod_mul(temp, challenge, witness.k, elgamal_.Order(), bn_ctx_);
    BN_mod_add(
        proof.message.k_response,
        proof.witness.k_randomness,
        temp,
        elgamal_.Order(),
        bn_ctx_);

    BN_mod_mul(temp, challenge, witness.r_u, elgamal_.Order(), bn_ctx_);
    BN_mod_add(
        proof.message.r_u_response,
        proof.witness.r_u_randomness,
        temp,
        elgamal_.Order(),
        bn_ctx_);

    BN_mod_mul(temp, challenge, witness.r_e, elgamal_.Order(), bn_ctx_);
    BN_mod_add(
        proof.message.r_e_response,
        proof.witness.r_e_randomness,
        temp,
        elgamal_.Order(),
        bn_ctx_);

    BN_clear_free(challenge);
    BN_clear_free(temp);
    EC_POINT_free(masked_u);
    EC_POINT_free(masked_e);
}

bool SameScalarArgument::VerifyProof(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance,
    const ProofMessage& proof_message) const
{
    if (!commitment_scheme_.IsValidCommitmentKey(commitment_key) ||
        !IsValidPublicInstance(commitment_key, public_instance) ||
        proof_message.k_response == nullptr ||
        proof_message.r_u_response == nullptr ||
        proof_message.r_e_response == nullptr ||
        !commitment_scheme_.IsValidCommitment(proof_message.random_u_commitment) ||
        !commitment_scheme_.IsValidCommitment(proof_message.random_e_commitment))
    {
        return false;
    }

    BIGNUM* challenge = BN_new();
    BIGNUM* challenge_plus_one = BN_new();
    EC_POINT* response_u = EC_POINT_new(commitment_key.group);
    EC_POINT* response_e = EC_POINT_new(commitment_key.group);
    Commitment expected_u;
    Commitment expected_e;
    EC_POINT* challenge_term_x = EC_POINT_new(commitment_key.group);
    EC_POINT* challenge_term_y = EC_POINT_new(commitment_key.group);
    EC_POINT* right_x = EC_POINT_new(commitment_key.group);
    EC_POINT* right_y = EC_POINT_new(commitment_key.group);
    if (challenge == nullptr ||
        challenge_plus_one == nullptr ||
        response_u == nullptr ||
        response_e == nullptr ||
        challenge_term_x == nullptr ||
        challenge_term_y == nullptr ||
        right_x == nullptr ||
        right_y == nullptr)
    {
        BN_clear_free(challenge);
        BN_clear_free(challenge_plus_one);
        EC_POINT_free(response_u);
        EC_POINT_free(response_e);
        EC_POINT_free(challenge_term_x);
        EC_POINT_free(challenge_term_y);
        EC_POINT_free(right_x);
        EC_POINT_free(right_y);
        return false;
    }

    GenerateChallenge(
        commitment_key,
        public_instance,
        proof_message,
        challenge);

    if (BN_copy(challenge_plus_one, challenge) == nullptr ||
        BN_add_word(challenge_plus_one, 1) != 1 ||
        BN_nnmod(
            challenge_plus_one,
            challenge_plus_one,
            elgamal_.Order(),
            bn_ctx_) != 1)
    {
        BN_clear_free(challenge);
        BN_clear_free(challenge_plus_one);
        EC_POINT_free(response_u);
        EC_POINT_free(response_e);
        EC_POINT_free(challenge_term_x);
        EC_POINT_free(challenge_term_y);
        EC_POINT_free(right_x);
        EC_POINT_free(right_y);
        return false;
    }

    const bool response_points_ok =
        EC_POINT_mul(
            commitment_key.group,
            response_u,
            nullptr,
            public_instance.u_a_sum,
            proof_message.k_response,
            bn_ctx_) == 1 &&
        EC_POINT_mul(
            commitment_key.group,
            response_e,
            nullptr,
            public_instance.e_a_sum,
            proof_message.k_response,
            bn_ctx_) == 1;
    if (!response_points_ok)
    {
        BN_clear_free(challenge);
        BN_clear_free(challenge_plus_one);
        EC_POINT_free(response_u);
        EC_POINT_free(response_e);
        EC_POINT_free(challenge_term_x);
        EC_POINT_free(challenge_term_y);
        EC_POINT_free(right_x);
        EC_POINT_free(right_y);
        return false;
    }

    EC_POINT_mul(
        commitment_key.group,
        challenge_term_x,
        nullptr,
        public_instance.u,
        challenge_plus_one,
        bn_ctx_);
    EC_POINT_add(
        commitment_key.group,
        response_u,
        response_u,
        challenge_term_x,
        bn_ctx_);
    commitment_scheme_.CommitWithRandomness(
        commitment_key,
        commitment_key.GU,
        response_u,
        proof_message.r_u_response,
        expected_u);

    EC_POINT_mul(
        commitment_key.group,
        challenge_term_x,
        nullptr,
        public_instance.e,
        challenge_plus_one,
        bn_ctx_);
    EC_POINT_add(
        commitment_key.group,
        response_e,
        response_e,
        challenge_term_x,
        bn_ctx_);
    commitment_scheme_.CommitWithRandomness(
        commitment_key,
        commitment_key.GE,
        response_e,
        proof_message.r_e_response,
        expected_e);

    EC_POINT_mul(
        commitment_key.group,
        challenge_term_x,
        nullptr,
        public_instance.cm_u.first,
        challenge,
        bn_ctx_);
    EC_POINT_add(
        commitment_key.group,
        right_x,
        proof_message.random_u_commitment.first,
        challenge_term_x,
        bn_ctx_);
    EC_POINT_mul(
        commitment_key.group,
        challenge_term_y,
        nullptr,
        public_instance.cm_u.second,
        challenge,
        bn_ctx_);
    EC_POINT_add(
        commitment_key.group,
        right_y,
        proof_message.random_u_commitment.second,
        challenge_term_y,
        bn_ctx_);
    const bool u_valid =
        EC_POINT_cmp(commitment_key.group, expected_u.first, right_x, bn_ctx_) == 0 &&
        EC_POINT_cmp(commitment_key.group, expected_u.second, right_y, bn_ctx_) == 0;

    EC_POINT_mul(
        commitment_key.group,
        challenge_term_x,
        nullptr,
        public_instance.cm_e.first,
        challenge,
        bn_ctx_);
    EC_POINT_add(
        commitment_key.group,
        right_x,
        proof_message.random_e_commitment.first,
        challenge_term_x,
        bn_ctx_);
    EC_POINT_mul(
        commitment_key.group,
        challenge_term_y,
        nullptr,
        public_instance.cm_e.second,
        challenge,
        bn_ctx_);
    EC_POINT_add(
        commitment_key.group,
        right_y,
        proof_message.random_e_commitment.second,
        challenge_term_y,
        bn_ctx_);
    const bool e_valid =
        EC_POINT_cmp(commitment_key.group, expected_e.first, right_x, bn_ctx_) == 0 &&
        EC_POINT_cmp(commitment_key.group, expected_e.second, right_y, bn_ctx_) == 0;

    BN_clear_free(challenge);
    BN_clear_free(challenge_plus_one);
    EC_POINT_free(response_u);
    EC_POINT_free(response_e);
    EC_POINT_free(challenge_term_x);
    EC_POINT_free(challenge_term_y);
    EC_POINT_free(right_x);
    EC_POINT_free(right_y);
    return u_valid && e_valid;
}

bool SameScalarArgument::VerifyProof(
    const CommitmentKey& commitment_key,
    const Proof& proof) const
{
    return VerifyProof(
        commitment_key,
        proof.public_instance,
        proof.message);
}

void SameScalarArgument::GenerateChallenge(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance,
    const ProofMessage& proof_message,
    BIGNUM* challenge) const
{
    std::string transcript;
    AppendPoint(transcript, commitment_key.group, commitment_key.GU);
    AppendPoint(transcript, commitment_key.group, commitment_key.GE);
    AppendPoint(transcript, commitment_key.group, commitment_key.H);
    const std::size_t ciphertext_count = public_instance.ciphertexts.size();
    transcript.append(
        reinterpret_cast<const char*>(&ciphertext_count),
        sizeof(ciphertext_count));
    for (std::size_t i = 0; i < ciphertext_count; ++i)
    {
        AppendPoint(
            transcript,
            commitment_key.group,
            public_instance.ciphertexts[i].u);
        AppendPoint(
            transcript,
            commitment_key.group,
            public_instance.ciphertexts[i].e);
        AppendScalar(transcript, public_instance.a[i]);
    }
    AppendPoint(transcript, commitment_key.group, public_instance.u);
    AppendPoint(transcript, commitment_key.group, public_instance.e);
    AppendPoint(transcript, commitment_key.group, public_instance.u_a_sum);
    AppendPoint(transcript, commitment_key.group, public_instance.e_a_sum);
    AppendPoint(transcript, commitment_key.group, public_instance.cm_u.first);
    AppendPoint(transcript, commitment_key.group, public_instance.cm_u.second);
    AppendPoint(transcript, commitment_key.group, public_instance.cm_e.first);
    AppendPoint(transcript, commitment_key.group, public_instance.cm_e.second);
    AppendPoint(transcript, commitment_key.group, proof_message.random_u_commitment.first);
    AppendPoint(transcript, commitment_key.group, proof_message.random_u_commitment.second);
    AppendPoint(transcript, commitment_key.group, proof_message.random_e_commitment.first);
    AppendPoint(transcript, commitment_key.group, proof_message.random_e_commitment.second);

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), challenge);
    BN_nnmod(challenge, challenge, elgamal_.Order(), bn_ctx_);
}

void SameScalarArgument::AppendPoint(
    std::string& transcript,
    const EC_GROUP* group,
    const EC_POINT* point) const
{
    ThrowIf(
        group == nullptr || point == nullptr,
        "SameScalar transcript point is not initialized");

    const std::size_t point_size = EC_POINT_point2oct(
        group,
        point,
        POINT_CONVERSION_COMPRESSED,
        nullptr,
        0,
        bn_ctx_);
    ThrowIf(point_size == 0, "SameScalar transcript point size failed");

    std::vector<unsigned char> encoded(point_size);
    ThrowIf(
        EC_POINT_point2oct(
            group,
            point,
            POINT_CONVERSION_COMPRESSED,
            encoded.data(),
            encoded.size(),
            bn_ctx_) != point_size,
        "SameScalar transcript point encoding failed");

    transcript.append(reinterpret_cast<const char*>(&point_size), sizeof(point_size));
    transcript.append(
        reinterpret_cast<const char*>(encoded.data()),
        encoded.size());
}

void SameScalarArgument::AppendScalar(
    std::string& transcript,
    const BIGNUM* scalar) const
{
    ThrowIf(scalar == nullptr, "SameScalar transcript scalar is not initialized");

    const std::size_t scalar_size = BN_num_bytes(scalar);
    transcript.append(
        reinterpret_cast<const char*>(&scalar_size),
        sizeof(scalar_size));
    if (scalar_size == 0)
    {
        return;
    }

    std::vector<unsigned char> encoded(scalar_size);
    ThrowIf(
        BN_bn2bin(scalar, encoded.data()) != static_cast<int>(scalar_size),
        "SameScalar transcript scalar encoding failed");
    transcript.append(
        reinterpret_cast<const char*>(encoded.data()),
        encoded.size());
}

bool SameScalarArgument::IsValidPublicInstance(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance) const
{
    const EC_GROUP* expected_group = elgamal_.Group();
    const bool basic_statement_ok = commitment_key.group == expected_group &&
        public_instance.group == expected_group &&
        public_instance.group == commitment_key.group &&
        !public_instance.ciphertexts.empty() &&
        public_instance.ciphertexts.size() == public_instance.a.size() &&
        public_instance.u != nullptr &&
        public_instance.e != nullptr &&
        public_instance.u_a_sum != nullptr &&
        public_instance.e_a_sum != nullptr &&
        EC_POINT_is_on_curve(expected_group, public_instance.u, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(expected_group, public_instance.e, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(expected_group, public_instance.u_a_sum, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(expected_group, public_instance.e_a_sum, bn_ctx_) == 1 &&
        EC_POINT_is_at_infinity(expected_group, public_instance.u) != 1 &&
        EC_POINT_is_at_infinity(expected_group, public_instance.e) != 1 &&
        EC_POINT_is_at_infinity(expected_group, public_instance.u_a_sum) != 1 &&
        EC_POINT_is_at_infinity(expected_group, public_instance.e_a_sum) != 1 &&
        public_instance.cm_u.group == expected_group &&
        public_instance.cm_e.group == expected_group &&
        commitment_scheme_.IsValidCommitment(public_instance.cm_u) &&
        commitment_scheme_.IsValidCommitment(public_instance.cm_e);
    if (!basic_statement_ok)
    {
        return false;
    }

    for (std::size_t i = 0; i < public_instance.ciphertexts.size(); ++i)
    {
        const Ciphertext& ciphertext = public_instance.ciphertexts[i];
        const BIGNUM* exponent = public_instance.a[i];
        if (exponent == nullptr ||
            ciphertext.group != expected_group ||
            !elgamal_.IsValidCiphertext(ciphertext))
        {
            return false;
        }
    }
    return true;
}
