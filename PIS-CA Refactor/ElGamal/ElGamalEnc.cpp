#include "ElGamalEnc.h"

#include <stdexcept>
#include <utility>

#include <openssl/rand.h>
#include <openssl/sha.h>

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

ElGamalEnc::PublicKey::PublicKey(const PublicKey& other)
    : group(other.group),
      generator(DuplicatePoint(other.group, other.generator)),
      g(DuplicatePoint(other.group, other.g)),
      pk(DuplicatePoint(other.group, other.pk))
{
}

ElGamalEnc::PublicKey& ElGamalEnc::PublicKey::operator=(const PublicKey& other)
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT* new_generator = DuplicatePoint(other.group, other.generator);
    EC_POINT* new_g = DuplicatePoint(other.group, other.g);
    EC_POINT* new_pk = DuplicatePoint(other.group, other.pk);
    EC_POINT_free(generator);
    EC_POINT_free(g);
    EC_POINT_free(pk);
    group = other.group;
    generator = new_generator;
    g = new_g;
    pk = new_pk;
    return *this;
}

ElGamalEnc::PublicKey::PublicKey(PublicKey&& other) noexcept
    : group(other.group), generator(other.generator), g(other.g), pk(other.pk)
{
    other.group = nullptr;
    other.generator = nullptr;
    other.g = nullptr;
    other.pk = nullptr;
}

ElGamalEnc::PublicKey& ElGamalEnc::PublicKey::operator=(PublicKey&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT_free(generator);
    EC_POINT_free(g);
    EC_POINT_free(pk);
    group = other.group;
    generator = other.generator;
    g = other.g;
    pk = other.pk;
    other.group = nullptr;
    other.generator = nullptr;
    other.g = nullptr;
    other.pk = nullptr;
    return *this;
}

ElGamalEnc::PublicKey::~PublicKey()
{
    EC_POINT_free(generator);
    EC_POINT_free(g);
    EC_POINT_free(pk);
}

ElGamalEnc::SecretKey::SecretKey()
    : sk(BN_new())
{
    ThrowIf(sk == nullptr, "ElGamal secret-key allocation failed");
}

ElGamalEnc::SecretKey::SecretKey(const SecretKey& other)
    : sk(other.sk == nullptr ? nullptr : BN_dup(other.sk))
{
    ThrowIf(other.sk != nullptr && sk == nullptr, "ElGamal secret-key copy failed");
}

ElGamalEnc::SecretKey& ElGamalEnc::SecretKey::operator=(const SecretKey& other)
{
    if (this == &other)
    {
        return *this;
    }

    BIGNUM* new_sk = other.sk == nullptr ? nullptr : BN_dup(other.sk);
    ThrowIf(other.sk != nullptr && new_sk == nullptr, "ElGamal secret-key copy failed");
    BN_clear_free(sk);
    sk = new_sk;
    return *this;
}

ElGamalEnc::SecretKey::SecretKey(SecretKey&& other) noexcept
    : sk(other.sk)
{
    other.sk = nullptr;
}

ElGamalEnc::SecretKey& ElGamalEnc::SecretKey::operator=(SecretKey&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    BN_clear_free(sk);
    sk = other.sk;
    other.sk = nullptr;
    return *this;
}

ElGamalEnc::SecretKey::~SecretKey()
{
    BN_clear_free(sk);
}

ElGamalEnc::CommitmentKey::CommitmentKey(const CommitmentKey& other)
    : group(other.group),
      g(DuplicatePoint(other.group, other.g)),
      h(DuplicatePoint(other.group, other.h))
{
}

ElGamalEnc::CommitmentKey& ElGamalEnc::CommitmentKey::operator=(
    const CommitmentKey& other)
{
    if (this == &other)
    {
        return *this;
    }
    EC_POINT* new_g = DuplicatePoint(other.group, other.g);
    EC_POINT* new_h = DuplicatePoint(other.group, other.h);
    EC_POINT_free(g);
    EC_POINT_free(h);
    group = other.group;
    g = new_g;
    h = new_h;
    return *this;
}

ElGamalEnc::CommitmentKey::CommitmentKey(CommitmentKey&& other) noexcept
    : group(other.group), g(other.g), h(other.h)
{
    other.group = nullptr;
    other.g = nullptr;
    other.h = nullptr;
}

ElGamalEnc::CommitmentKey& ElGamalEnc::CommitmentKey::operator=(
    CommitmentKey&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }
    EC_POINT_free(g);
    EC_POINT_free(h);
    group = other.group;
    g = other.g;
    h = other.h;
    other.group = nullptr;
    other.g = nullptr;
    other.h = nullptr;
    return *this;
}

ElGamalEnc::CommitmentKey::~CommitmentKey()
{
    EC_POINT_free(g);
    EC_POINT_free(h);
}

ElGamalEnc::Commitment::Commitment(const Commitment& other)
    : group(other.group), value(DuplicatePoint(other.group, other.value))
{
}

ElGamalEnc::Commitment& ElGamalEnc::Commitment::operator=(
    const Commitment& other)
{
    if (this == &other)
    {
        return *this;
    }
    EC_POINT* new_value = DuplicatePoint(other.group, other.value);
    EC_POINT_free(value);
    group = other.group;
    value = new_value;
    return *this;
}

ElGamalEnc::Commitment::Commitment(Commitment&& other) noexcept
    : group(other.group), value(other.value)
{
    other.group = nullptr;
    other.value = nullptr;
}

ElGamalEnc::Commitment& ElGamalEnc::Commitment::operator=(
    Commitment&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }
    EC_POINT_free(value);
    group = other.group;
    value = other.value;
    other.group = nullptr;
    other.value = nullptr;
    return *this;
}

ElGamalEnc::Commitment::~Commitment()
{
    EC_POINT_free(value);
}

ElGamalEnc::Ciphertext::Ciphertext(const Ciphertext& other)
    : group(other.group),
      u(DuplicatePoint(other.group, other.u)),
      e(DuplicatePoint(other.group, other.e))
{
}

ElGamalEnc::Ciphertext& ElGamalEnc::Ciphertext::operator=(const Ciphertext& other)
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT* new_u = DuplicatePoint(other.group, other.u);
    EC_POINT* new_e = DuplicatePoint(other.group, other.e);
    EC_POINT_free(u);
    EC_POINT_free(e);
    group = other.group;
    u = new_u;
    e = new_e;
    return *this;
}

ElGamalEnc::Ciphertext::Ciphertext(Ciphertext&& other) noexcept
    : group(other.group), u(other.u), e(other.e)
{
    other.group = nullptr;
    other.u = nullptr;
    other.e = nullptr;
}

ElGamalEnc::Ciphertext& ElGamalEnc::Ciphertext::operator=(Ciphertext&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT_free(u);
    EC_POINT_free(e);
    group = other.group;
    u = other.u;
    e = other.e;
    other.group = nullptr;
    other.u = nullptr;
    other.e = nullptr;
    return *this;
}

ElGamalEnc::Ciphertext::~Ciphertext()
{
    EC_POINT_free(u);
    EC_POINT_free(e);
}

ElGamalEnc::ElGamalEnc(int curve_nid)
    : group_(EC_GROUP_new_by_curve_name(curve_nid)),
      bn_ctx_(BN_CTX_new()),
      order_(BN_new())
{
    ThrowIf(group_ == nullptr || bn_ctx_ == nullptr || order_ == nullptr,
        "ElGamal curve allocation failed");
    ThrowIf(EC_GROUP_get_order(group_, order_, bn_ctx_) != 1,
        "ElGamal curve-order lookup failed");
}

ElGamalEnc::~ElGamalEnc()
{
    BN_clear_free(order_);
    BN_CTX_free(bn_ctx_);
    EC_GROUP_free(group_);
}

void ElGamalEnc::RandomOracle(
    std::array<std::uint8_t, HashBytes>& challenge,
    const std::string& input) const
{
    SHA256(
        reinterpret_cast<const unsigned char*>(input.data()),
        input.size(),
        challenge.data());
}

void ElGamalEnc::Setup(PublicKey& public_key) const
{
    public_key.group = group_;
    EC_POINT_free(public_key.generator);
    EC_POINT_free(public_key.g);
    EC_POINT_free(public_key.pk);
    public_key.generator = EC_POINT_dup(EC_GROUP_get0_generator(group_), group_);
    public_key.g = EC_POINT_new(group_);
    public_key.pk = EC_POINT_new(group_);
    ThrowIf(
        public_key.generator == nullptr ||
            public_key.g == nullptr ||
            public_key.pk == nullptr,
        "ElGamal public-key allocation failed");
    GenerateRandomGroupElement(public_key.g);
    ThrowIf(EC_POINT_set_to_infinity(group_, public_key.pk) != 1,
        "ElGamal public-key initialization failed");
}

void ElGamalEnc::GenerateKeys(PublicKey& public_key, SecretKey& secret_key) const
{
    if (public_key.group != group_ ||
        public_key.generator == nullptr ||
        public_key.g == nullptr ||
        public_key.pk == nullptr)
    {
        Setup(public_key);
    }
    ThrowIf(secret_key.sk == nullptr, "ElGamal secret key is not allocated");

    GenerateRandomScalar(secret_key.sk);
    ThrowIf(EC_POINT_mul(
        group_,
        public_key.pk,
        nullptr,
        public_key.generator,
        secret_key.sk,
        bn_ctx_) != 1,
        "ElGamal key generation failed");
}

void ElGamalEnc::GenerateKeys(
    PublicKey& public_key,
    SecretKey& secret_key,
    CommitmentKey& commitment_key) const
{
    GenerateKeys(public_key, secret_key);

    commitment_key.group = group_;
    EC_POINT_free(commitment_key.g);
    EC_POINT_free(commitment_key.h);
    commitment_key.g = EC_POINT_new(group_);
    commitment_key.h = EC_POINT_new(group_);
    ThrowIf(
        commitment_key.g == nullptr ||
            commitment_key.h == nullptr,
        "ElGamal commitment-key allocation failed");

    GenerateRandomGroupElement(commitment_key.g);
    int generators_equal = 0;
    do
    {
        GenerateRandomGroupElement(commitment_key.h);
        generators_equal = EC_POINT_cmp(
            group_,
            commitment_key.g,
            commitment_key.h,
            bn_ctx_);
        ThrowIf(
            generators_equal < 0,
            "ElGamal commitment generator comparison failed");
    }
    while (generators_equal == 0);
}

void ElGamalEnc::GenerateRandomScalar(BIGNUM* scalar) const
{
    ThrowIf(scalar == nullptr, "ElGamal scalar is null");
    do
    {
        ThrowIf(BN_priv_rand_range(scalar, order_) != 1,
            "ElGamal random-scalar generation failed");
    }
    while (BN_is_zero(scalar));
}

void ElGamalEnc::GenerateRandomGroupElement(EC_POINT* point) const
{
    ThrowIf(point == nullptr, "ElGamal group element is null");

    BN_CTX_start(bn_ctx_);
    BIGNUM* field_modulus = BN_CTX_get(bn_ctx_);
    BIGNUM* curve_a = BN_CTX_get(bn_ctx_);
    BIGNUM* curve_b = BN_CTX_get(bn_ctx_);
    BIGNUM* x = BN_CTX_get(bn_ctx_);
    BIGNUM* cofactor = BN_CTX_get(bn_ctx_);
    ThrowIf(
        field_modulus == nullptr ||
            curve_a == nullptr ||
            curve_b == nullptr ||
            x == nullptr ||
            cofactor == nullptr,
        "ElGamal random group-element allocation failed");
    ThrowIf(
        EC_GROUP_get_curve(
            group_,
            field_modulus,
            curve_a,
            curve_b,
            bn_ctx_) != 1 ||
            EC_GROUP_get_cofactor(group_, cofactor, bn_ctx_) != 1,
        "ElGamal curve parameter lookup failed");

    EC_POINT* candidate = EC_POINT_new(group_);
    EC_POINT* subgroup_check = EC_POINT_new(group_);
    ThrowIf(
        candidate == nullptr || subgroup_check == nullptr,
        "ElGamal random group-element point allocation failed");

    for (;;)
    {
        unsigned char y_bit = 0;
        ThrowIf(
            BN_priv_rand_range(x, field_modulus) != 1 ||
                RAND_priv_bytes(&y_bit, 1) != 1,
            "ElGamal random group-element coordinate generation failed");

        if (EC_POINT_set_compressed_coordinates(
                group_,
                candidate,
                x,
                y_bit & 1,
                bn_ctx_) != 1)
        {
            continue;
        }

        if (!BN_is_one(cofactor))
        {
            ThrowIf(
                EC_POINT_mul(
                    group_,
                    candidate,
                    nullptr,
                    candidate,
                    cofactor,
                    bn_ctx_) != 1,
                "ElGamal random group-element cofactor clearing failed");
        }

        if (EC_POINT_is_at_infinity(group_, candidate) == 1)
        {
            continue;
        }

        ThrowIf(
            EC_POINT_mul(
                group_,
                subgroup_check,
                nullptr,
                candidate,
                order_,
                bn_ctx_) != 1,
            "ElGamal random group-element subgroup check failed");
        if (EC_POINT_is_at_infinity(group_, subgroup_check) != 1)
        {
            continue;
        }

        ThrowIf(
            EC_POINT_copy(point, candidate) != 1,
            "ElGamal random group-element copy failed");
        break;
    }

    EC_POINT_free(candidate);
    EC_POINT_free(subgroup_check);
    BN_CTX_end(bn_ctx_);
}

void ElGamalEnc::GenerateCommitment(
    const CommitmentKey& commitment_key,
    const BIGNUM* plaintext,
    BIGNUM* randomness,
    Commitment& commitment) const
{
    GenerateRandomScalar(randomness);
    GenerateCommitmentWithRandomness(
        commitment_key,
        plaintext,
        randomness,
        commitment);
}

void ElGamalEnc::GenerateCommitmentWithRandomness(
    const CommitmentKey& commitment_key,
    const BIGNUM* plaintext,
    const BIGNUM* randomness,
    Commitment& commitment) const
{
    ThrowIf(
        !IsValidCommitmentKey(commitment_key),
        "ElGamal commitment key is invalid");
    ThrowIf(
        plaintext == nullptr || randomness == nullptr,
        "ElGamal commitment input is null");

    PrepareCommitment(commitment);
    BN_CTX_start(bn_ctx_);
    BIGNUM* normalized_plaintext = BN_CTX_get(bn_ctx_);
    BIGNUM* normalized_randomness = BN_CTX_get(bn_ctx_);
    EC_POINT* randomness_term = EC_POINT_new(group_);
    ThrowIf(
        normalized_plaintext == nullptr ||
            normalized_randomness == nullptr ||
            randomness_term == nullptr,
        "ElGamal commitment temporary allocation failed");

    NormalizeScalar(plaintext, normalized_plaintext);
    NormalizeScalar(randomness, normalized_randomness);
    ThrowIf(
        EC_POINT_mul(
            group_,
            commitment.value,
            nullptr,
            commitment_key.g,
            normalized_plaintext,
            bn_ctx_) != 1 ||
            EC_POINT_mul(
                group_,
                randomness_term,
                nullptr,
                commitment_key.h,
                normalized_randomness,
                bn_ctx_) != 1 ||
            EC_POINT_add(
                group_,
                commitment.value,
                commitment.value,
                randomness_term,
                bn_ctx_) != 1,
        "ElGamal commitment generation failed");

    EC_POINT_free(randomness_term);
    BN_CTX_end(bn_ctx_);
}

void ElGamalEnc::Encrypt(
    const PublicKey& public_key,
    const EC_POINT* plaintext,
    BIGNUM* randomness,
    Ciphertext& ciphertext) const
{
    GenerateRandomScalar(randomness);
    EncryptWithRandomness(public_key, plaintext, randomness, ciphertext);
}

void ElGamalEnc::EncryptWithRandomness(
    const PublicKey& public_key,
    const EC_POINT* plaintext,
    const BIGNUM* randomness,
    Ciphertext& ciphertext) const
{
    ThrowIf(!IsValidPublicKey(public_key), "ElGamal public key is invalid");
    ThrowIf(plaintext == nullptr ||
        EC_POINT_is_on_curve(group_, plaintext, bn_ctx_) != 1,
        "ElGamal plaintext point is invalid");
    ThrowIf(randomness == nullptr, "ElGamal encryption randomness is null");

    PrepareCiphertext(ciphertext);
    BN_CTX_start(bn_ctx_);
    BIGNUM* normalized_randomness = BN_CTX_get(bn_ctx_);
    EC_POINT* shared_secret = EC_POINT_new(group_);
    ThrowIf(normalized_randomness == nullptr || shared_secret == nullptr,
        "ElGamal encryption temporary allocation failed");

    NormalizeScalar(randomness, normalized_randomness);
    ThrowIf(EC_POINT_mul(
        group_,
        ciphertext.u,
        nullptr,
        public_key.generator,
        normalized_randomness,
        bn_ctx_) != 1,
        "ElGamal ciphertext u computation failed");
    ThrowIf(EC_POINT_mul(
        group_,
        shared_secret,
        nullptr,
        public_key.pk,
        normalized_randomness,
        bn_ctx_) != 1 ||
        EC_POINT_add(group_, ciphertext.e, plaintext, shared_secret, bn_ctx_) != 1,
        "ElGamal ciphertext e computation failed");

    EC_POINT_free(shared_secret);
    BN_CTX_end(bn_ctx_);
}

void ElGamalEnc::Decrypt(
    const PublicKey& public_key,
    const SecretKey& secret_key,
    const Ciphertext& ciphertext,
    EC_POINT* plaintext) const
{
    ThrowIf(!IsValidPublicKey(public_key), "ElGamal public key is invalid");
    ThrowIf(secret_key.sk == nullptr || plaintext == nullptr,
        "ElGamal decryption input is null");
    ThrowIf(!IsValidCiphertext(ciphertext), "ElGamal ciphertext is invalid");

    EC_POINT* shared_secret = EC_POINT_new(group_);
    ThrowIf(shared_secret == nullptr, "ElGamal decryption temporary allocation failed");
    ThrowIf(EC_POINT_mul(
        group_,
        shared_secret,
        nullptr,
        ciphertext.u,
        secret_key.sk,
        bn_ctx_) != 1 ||
        EC_POINT_invert(group_, shared_secret, bn_ctx_) != 1 ||
        EC_POINT_add(group_, plaintext, ciphertext.e, shared_secret, bn_ctx_) != 1,
        "ElGamal decryption failed");
    EC_POINT_free(shared_secret);
}

void ElGamalEnc::EncodePlaintext(
    const PublicKey& public_key,
    const BIGNUM* scalar,
    EC_POINT* plaintext) const
{
    ThrowIf(!IsValidPublicKey(public_key), "ElGamal public key is invalid");
    ThrowIf(scalar == nullptr || plaintext == nullptr, "ElGamal plaintext input is null");

    BN_CTX_start(bn_ctx_);
    BIGNUM* normalized_scalar = BN_CTX_get(bn_ctx_);
    ThrowIf(normalized_scalar == nullptr, "ElGamal scalar allocation failed");
    NormalizeScalar(scalar, normalized_scalar);
    ThrowIf(EC_POINT_mul(
        group_,
        plaintext,
        nullptr,
        public_key.generator,
        normalized_scalar,
        bn_ctx_) != 1,
        "ElGamal plaintext encoding failed");
    BN_CTX_end(bn_ctx_);
}

void ElGamalEnc::HomomorphicAdd(
    const PublicKey& public_key,
    Ciphertext& result,
    const Ciphertext& left,
    const Ciphertext& right) const
{
    ThrowIf(!IsValidPublicKey(public_key) ||
        !IsValidCiphertext(left) ||
        !IsValidCiphertext(right),
        "ElGamal homomorphic-add input is invalid");

    Ciphertext sum;
    PrepareCiphertext(sum);
    ThrowIf(EC_POINT_add(group_, sum.u, left.u, right.u, bn_ctx_) != 1 ||
        EC_POINT_add(group_, sum.e, left.e, right.e, bn_ctx_) != 1,
        "ElGamal homomorphic addition failed");
    result = std::move(sum);
}

void ElGamalEnc::HomomorphicSubtract(
    const PublicKey& public_key,
    Ciphertext& result,
    const Ciphertext& left,
    const Ciphertext& right) const
{
    ThrowIf(!IsValidPublicKey(public_key) ||
        !IsValidCiphertext(left) ||
        !IsValidCiphertext(right),
        "ElGamal homomorphic-subtract input is invalid");

    Ciphertext difference;
    PrepareCiphertext(difference);
    EC_POINT* negative_u = EC_POINT_dup(right.u, group_);
    EC_POINT* negative_e = EC_POINT_dup(right.e, group_);
    ThrowIf(negative_u == nullptr || negative_e == nullptr,
        "ElGamal subtraction temporary allocation failed");
    ThrowIf(EC_POINT_invert(group_, negative_u, bn_ctx_) != 1 ||
        EC_POINT_invert(group_, negative_e, bn_ctx_) != 1 ||
        EC_POINT_add(group_, difference.u, left.u, negative_u, bn_ctx_) != 1 ||
        EC_POINT_add(group_, difference.e, left.e, negative_e, bn_ctx_) != 1,
        "ElGamal homomorphic subtraction failed");
    EC_POINT_free(negative_u);
    EC_POINT_free(negative_e);
    result = std::move(difference);
}

void ElGamalEnc::ScalarMultiply(
    const PublicKey& public_key,
    Ciphertext& result,
    const Ciphertext& ciphertext,
    const BIGNUM* scalar) const
{
    ThrowIf(!IsValidPublicKey(public_key) ||
        !IsValidCiphertext(ciphertext) ||
        scalar == nullptr,
        "ElGamal scalar-multiply input is invalid");

    Ciphertext product;
    PrepareCiphertext(product);
    BN_CTX_start(bn_ctx_);
    BIGNUM* normalized_scalar = BN_CTX_get(bn_ctx_);
    ThrowIf(normalized_scalar == nullptr, "ElGamal scalar allocation failed");
    NormalizeScalar(scalar, normalized_scalar);
    ThrowIf(EC_POINT_mul(
        group_,
        product.u,
        nullptr,
        ciphertext.u,
        normalized_scalar,
        bn_ctx_) != 1 ||
        EC_POINT_mul(
            group_,
            product.e,
            nullptr,
            ciphertext.e,
            normalized_scalar,
            bn_ctx_) != 1,
        "ElGamal scalar multiplication failed");
    BN_CTX_end(bn_ctx_);
    result = std::move(product);
}

bool ElGamalEnc::IsValidPublicKey(const PublicKey& public_key) const
{
    return public_key.group == group_ &&
        public_key.generator != nullptr &&
        public_key.g != nullptr &&
        public_key.pk != nullptr &&
        EC_POINT_is_on_curve(group_, public_key.generator, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group_, public_key.g, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group_, public_key.pk, bn_ctx_) == 1 &&
        EC_POINT_is_at_infinity(group_, public_key.generator) == 0 &&
        EC_POINT_is_at_infinity(group_, public_key.g) == 0 &&
        EC_POINT_is_at_infinity(group_, public_key.pk) == 0;
}

bool ElGamalEnc::IsValidCommitmentKey(
    const CommitmentKey& commitment_key) const
{
    return commitment_key.group == group_ &&
        commitment_key.g != nullptr &&
        commitment_key.h != nullptr &&
        EC_POINT_is_on_curve(group_, commitment_key.g, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group_, commitment_key.h, bn_ctx_) == 1 &&
        EC_POINT_is_at_infinity(group_, commitment_key.g) == 0 &&
        EC_POINT_is_at_infinity(group_, commitment_key.h) == 0;
}

bool ElGamalEnc::IsValidCommitment(const Commitment& commitment) const
{
    return commitment.group == group_ &&
        commitment.value != nullptr &&
        EC_POINT_is_on_curve(group_, commitment.value, bn_ctx_) == 1 &&
        EC_POINT_is_at_infinity(group_, commitment.value) == 0;
}

bool ElGamalEnc::IsValidCiphertext(const Ciphertext& ciphertext) const
{
    return ciphertext.group == group_ &&
        ciphertext.u != nullptr &&
        ciphertext.e != nullptr &&
        EC_POINT_is_on_curve(group_, ciphertext.u, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group_, ciphertext.e, bn_ctx_) == 1;
}

bool ElGamalEnc::PointsEqual(const EC_POINT* left, const EC_POINT* right) const
{
    return left != nullptr &&
        right != nullptr &&
        EC_POINT_cmp(group_, left, right, bn_ctx_) == 0;
}

const EC_GROUP* ElGamalEnc::Group() const
{
    return group_;
}

const BIGNUM* ElGamalEnc::Order() const
{
    return order_;
}

EC_POINT* ElGamalEnc::NewPoint() const
{
    EC_POINT* point = EC_POINT_new(group_);
    ThrowIf(point == nullptr, "ElGamal point allocation failed");
    return point;
}

void ElGamalEnc::PrepareCommitment(Commitment& commitment) const
{
    if (commitment.group != group_)
    {
        EC_POINT_free(commitment.value);
        commitment.value = nullptr;
        commitment.group = group_;
    }
    if (commitment.value == nullptr)
    {
        commitment.value = EC_POINT_new(group_);
    }
    ThrowIf(
        commitment.value == nullptr,
        "ElGamal commitment allocation failed");
}

void ElGamalEnc::PrepareCiphertext(Ciphertext& ciphertext) const
{
    if (ciphertext.group != group_)
    {
        EC_POINT_free(ciphertext.u);
        EC_POINT_free(ciphertext.e);
        ciphertext.u = nullptr;
        ciphertext.e = nullptr;
        ciphertext.group = group_;
    }
    if (ciphertext.u == nullptr)
    {
        ciphertext.u = EC_POINT_new(group_);
    }
    if (ciphertext.e == nullptr)
    {
        ciphertext.e = EC_POINT_new(group_);
    }
    ThrowIf(ciphertext.u == nullptr || ciphertext.e == nullptr,
        "ElGamal ciphertext allocation failed");
}

void ElGamalEnc::NormalizeScalar(const BIGNUM* scalar, BIGNUM* normalized) const
{
    ThrowIf(BN_nnmod(normalized, scalar, order_, bn_ctx_) != 1,
        "ElGamal scalar reduction failed");
}
