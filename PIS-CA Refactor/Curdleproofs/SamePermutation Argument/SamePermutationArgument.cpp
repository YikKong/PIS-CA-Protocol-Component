#include "SamePermutationArgument.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <utility>

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

std::vector<EC_POINT*> DuplicatePointVector(
    const EC_GROUP* group,
    const std::vector<EC_POINT*>& points)
{
    std::vector<EC_POINT*> result;
    result.reserve(points.size());
    try
    {
        for (const EC_POINT* point : points)
        {
            EC_POINT* copy = DuplicatePoint(group, point);
            ThrowIf(point != nullptr && copy == nullptr, "SamePerm point copy failed");
            result.emplace_back(copy);
        }
    }
    catch (...)
    {
        for (EC_POINT* point : result)
        {
            EC_POINT_free(point);
        }
        throw;
    }
    return result;
}

std::vector<BIGNUM*> DuplicateBNVector(const std::vector<BIGNUM*>& values)
{
    std::vector<BIGNUM*> result;
    result.reserve(values.size());
    try
    {
        for (const BIGNUM* value : values)
        {
            BIGNUM* copy = DuplicateBN(value);
            ThrowIf(value != nullptr && copy == nullptr, "SamePerm scalar copy failed");
            result.emplace_back(copy);
        }
    }
    catch (...)
    {
        for (BIGNUM* value : result)
        {
            BN_clear_free(value);
        }
        throw;
    }
    return result;
}

void FreePointVector(std::vector<EC_POINT*>& points)
{
    for (EC_POINT* point : points)
    {
        EC_POINT_free(point);
    }
    points.clear();
}

void FreeBNVector(std::vector<BIGNUM*>& values)
{
    for (BIGNUM* value : values)
    {
        BN_clear_free(value);
    }
    values.clear();
}

bool IsPowerOfTwo(std::size_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}
}

SamePermutationArgument::GrandProductPublicInstance::GrandProductPublicInstance(
    const GrandProductPublicInstance& other)
    : group(other.group),
      g(DuplicatePointVector(other.group, other.g)),
      h(DuplicatePoint(other.group, other.h)),
      B(other.B),
      p(DuplicateBN(other.p))
{
}

SamePermutationArgument::GrandProductPublicInstance&
SamePermutationArgument::GrandProductPublicInstance::operator=(
    const GrandProductPublicInstance& other)
{
    if (this == &other)
    {
        return *this;
    }

    GrandProductPublicInstance copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::GrandProductPublicInstance::GrandProductPublicInstance(
    GrandProductPublicInstance&& other) noexcept
    : group(other.group),
      g(std::move(other.g)),
      h(other.h),
      B(std::move(other.B)),
      p(other.p)
{
    other.group = nullptr;
    other.h = nullptr;
    other.p = nullptr;
}

SamePermutationArgument::GrandProductPublicInstance&
SamePermutationArgument::GrandProductPublicInstance::operator=(
    GrandProductPublicInstance&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreePointVector(g);
    EC_POINT_free(h);
    BN_clear_free(p);
    group = other.group;
    g = std::move(other.g);
    h = other.h;
    B = std::move(other.B);
    p = other.p;
    other.group = nullptr;
    other.h = nullptr;
    other.p = nullptr;
    return *this;
}

SamePermutationArgument::GrandProductPublicInstance::~GrandProductPublicInstance()
{
    FreePointVector(g);
    EC_POINT_free(h);
    BN_clear_free(p);
}

SamePermutationArgument::GrandProductWitness::GrandProductWitness(
    const GrandProductWitness& other)
    : b(DuplicateBNVector(other.b)),
      r_B(DuplicateBN(other.r_B))
{
    ThrowIf(other.r_B != nullptr && r_B == nullptr, "SamePerm gprod r_B copy failed");
}

SamePermutationArgument::GrandProductWitness&
SamePermutationArgument::GrandProductWitness::operator=(const GrandProductWitness& other)
{
    if (this == &other)
    {
        return *this;
    }

    GrandProductWitness copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::GrandProductWitness::GrandProductWitness(
    GrandProductWitness&& other) noexcept
    : b(std::move(other.b)),
      r_B(other.r_B)
{
    other.r_B = nullptr;
}

SamePermutationArgument::GrandProductWitness&
SamePermutationArgument::GrandProductWitness::operator=(
    GrandProductWitness&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreeBNVector(b);
    BN_clear_free(r_B);
    b = std::move(other.b);
    r_B = other.r_B;
    other.r_B = nullptr;
    return *this;
}

SamePermutationArgument::GrandProductWitness::~GrandProductWitness()
{
    FreeBNVector(b);
    BN_clear_free(r_B);
}

SamePermutationArgument::InnerProductPublicInstance::InnerProductPublicInstance(
    const InnerProductPublicInstance& other)
    : group(other.group),
      G(DuplicatePointVector(other.group, other.G)),
      G_prime(DuplicatePointVector(other.group, other.G_prime)),
      H(DuplicatePoint(other.group, other.H)),
      h(DuplicatePoint(other.group, other.h)),
      C(other.C),
      D(other.D),
      z(DuplicateBN(other.z))
{
}

SamePermutationArgument::InnerProductPublicInstance&
SamePermutationArgument::InnerProductPublicInstance::operator=(
    const InnerProductPublicInstance& other)
{
    if (this == &other)
    {
        return *this;
    }

    InnerProductPublicInstance copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::InnerProductPublicInstance::InnerProductPublicInstance(
    InnerProductPublicInstance&& other) noexcept
    : group(other.group),
      G(std::move(other.G)),
      G_prime(std::move(other.G_prime)),
      H(other.H),
      h(other.h),
      C(std::move(other.C)),
      D(std::move(other.D)),
      z(other.z)
{
    other.group = nullptr;
    other.H = nullptr;
    other.h = nullptr;
    other.z = nullptr;
}

SamePermutationArgument::InnerProductPublicInstance&
SamePermutationArgument::InnerProductPublicInstance::operator=(
    InnerProductPublicInstance&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreePointVector(G);
    FreePointVector(G_prime);
    EC_POINT_free(H);
    EC_POINT_free(h);
    BN_clear_free(z);
    group = other.group;
    G = std::move(other.G);
    G_prime = std::move(other.G_prime);
    H = other.H;
    h = other.h;
    C = std::move(other.C);
    D = std::move(other.D);
    z = other.z;
    other.group = nullptr;
    other.H = nullptr;
    other.h = nullptr;
    other.z = nullptr;
    return *this;
}

SamePermutationArgument::InnerProductPublicInstance::~InnerProductPublicInstance()
{
    FreePointVector(G);
    FreePointVector(G_prime);
    EC_POINT_free(H);
    EC_POINT_free(h);
    BN_clear_free(z);
}

SamePermutationArgument::InnerProductWitness::InnerProductWitness(
    const InnerProductWitness& other)
    : c(DuplicateBNVector(other.c)),
      d(DuplicateBNVector(other.d))
{
}

SamePermutationArgument::InnerProductWitness&
SamePermutationArgument::InnerProductWitness::operator=(const InnerProductWitness& other)
{
    if (this == &other)
    {
        return *this;
    }

    InnerProductWitness copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::InnerProductWitness::InnerProductWitness(
    InnerProductWitness&& other) noexcept
    : c(std::move(other.c)),
      d(std::move(other.d))
{
}

SamePermutationArgument::InnerProductWitness&
SamePermutationArgument::InnerProductWitness::operator=(
    InnerProductWitness&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreeBNVector(c);
    FreeBNVector(d);
    c = std::move(other.c);
    d = std::move(other.d);
    return *this;
}

SamePermutationArgument::InnerProductWitness::~InnerProductWitness()
{
    FreeBNVector(c);
    FreeBNVector(d);
}

SamePermutationArgument::PublicInstance::PublicInstance(const PublicInstance& other)
    : group(other.group),
      g(DuplicatePointVector(other.group, other.g)),
      h(DuplicatePoint(other.group, other.h)),
      a(DuplicateBNVector(other.a)),
      n(DuplicateBNVector(other.n)),
      A(other.A),
      M(other.M),
      grand_product(other.grand_product),
      inner_product(other.inner_product)
{
}

SamePermutationArgument::PublicInstance&
SamePermutationArgument::PublicInstance::operator=(const PublicInstance& other)
{
    if (this == &other)
    {
        return *this;
    }

    PublicInstance copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::PublicInstance::PublicInstance(
    PublicInstance&& other) noexcept
    : group(other.group),
      g(std::move(other.g)),
      h(other.h),
      a(std::move(other.a)),
      n(std::move(other.n)),
      A(std::move(other.A)),
      M(std::move(other.M)),
      grand_product(std::move(other.grand_product)),
      inner_product(std::move(other.inner_product))
{
    other.group = nullptr;
    other.h = nullptr;
}

SamePermutationArgument::PublicInstance&
SamePermutationArgument::PublicInstance::operator=(PublicInstance&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreePointVector(g);
    FreeBNVector(a);
    FreeBNVector(n);
    EC_POINT_free(h);
    group = other.group;
    g = std::move(other.g);
    h = other.h;
    a = std::move(other.a);
    n = std::move(other.n);
    A = std::move(other.A);
    M = std::move(other.M);
    grand_product = std::move(other.grand_product);
    inner_product = std::move(other.inner_product);
    other.group = nullptr;
    other.h = nullptr;
    return *this;
}

SamePermutationArgument::PublicInstance::~PublicInstance()
{
    FreePointVector(g);
    FreeBNVector(a);
    FreeBNVector(n);
    EC_POINT_free(h);
}

SamePermutationArgument::Witness::Witness(const Witness& other)
    : permutation(other.permutation),
      sigma_a(DuplicateBNVector(other.sigma_a)),
      sigma_n(DuplicateBNVector(other.sigma_n)),
      r_A(DuplicateBN(other.r_A)),
      r_M(DuplicateBN(other.r_M)),
      grand_product(other.grand_product),
      inner_product(other.inner_product)
{
    ThrowIf(other.r_A != nullptr && r_A == nullptr, "SamePerm witness r_A copy failed");
    ThrowIf(other.r_M != nullptr && r_M == nullptr, "SamePerm witness r_M copy failed");
}

SamePermutationArgument::Witness&
SamePermutationArgument::Witness::operator=(const Witness& other)
{
    if (this == &other)
    {
        return *this;
    }

    Witness copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::Witness::Witness(Witness&& other) noexcept
    : permutation(std::move(other.permutation)),
      sigma_a(std::move(other.sigma_a)),
      sigma_n(std::move(other.sigma_n)),
      r_A(other.r_A),
      r_M(other.r_M),
      grand_product(std::move(other.grand_product)),
      inner_product(std::move(other.inner_product))
{
    other.r_A = nullptr;
    other.r_M = nullptr;
}

SamePermutationArgument::Witness&
SamePermutationArgument::Witness::operator=(Witness&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreeBNVector(sigma_a);
    FreeBNVector(sigma_n);
    BN_clear_free(r_A);
    BN_clear_free(r_M);
    permutation = std::move(other.permutation);
    sigma_a = std::move(other.sigma_a);
    sigma_n = std::move(other.sigma_n);
    r_A = other.r_A;
    r_M = other.r_M;
    grand_product = std::move(other.grand_product);
    inner_product = std::move(other.inner_product);
    other.r_A = nullptr;
    other.r_M = nullptr;
    return *this;
}

SamePermutationArgument::Witness::~Witness()
{
    FreeBNVector(sigma_a);
    FreeBNVector(sigma_n);
    BN_clear_free(r_A);
    BN_clear_free(r_M);
}

SamePermutationArgument::GrandProductProofMessage::GrandProductProofMessage(
    const GrandProductProofMessage& other)
    : group(other.group),
      B(DuplicatePoint(other.group, other.B)),
      C(DuplicatePoint(other.group, other.C)),
      r_p(DuplicateBN(other.r_p))
{
}

SamePermutationArgument::GrandProductProofMessage&
SamePermutationArgument::GrandProductProofMessage::operator=(
    const GrandProductProofMessage& other)
{
    if (this == &other)
    {
        return *this;
    }

    GrandProductProofMessage copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::GrandProductProofMessage::GrandProductProofMessage(
    GrandProductProofMessage&& other) noexcept
    : group(other.group),
      B(other.B),
      C(other.C),
      r_p(other.r_p)
{
    other.group = nullptr;
    other.B = nullptr;
    other.C = nullptr;
    other.r_p = nullptr;
}

SamePermutationArgument::GrandProductProofMessage&
SamePermutationArgument::GrandProductProofMessage::operator=(
    GrandProductProofMessage&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT_free(B);
    EC_POINT_free(C);
    BN_clear_free(r_p);
    group = other.group;
    B = other.B;
    C = other.C;
    r_p = other.r_p;
    other.group = nullptr;
    other.B = nullptr;
    other.C = nullptr;
    other.r_p = nullptr;
    return *this;
}

SamePermutationArgument::GrandProductProofMessage::~GrandProductProofMessage()
{
    EC_POINT_free(B);
    EC_POINT_free(C);
    BN_clear_free(r_p);
}

SamePermutationArgument::InnerProductProofMessage::InnerProductProofMessage()
    : c(BN_new()), d(BN_new()), r_h(BN_new())
{
    ThrowIf(c == nullptr || d == nullptr || r_h == nullptr,
        "SamePerm proof scalar allocation failed");
}

SamePermutationArgument::InnerProductProofMessage::InnerProductProofMessage(
    const InnerProductProofMessage& other)
    : group(other.group),
      A(DuplicatePoint(other.group, other.A)),
      B(DuplicatePoint(other.group, other.B)),
      L(DuplicatePointVector(other.group, other.L)),
      R(DuplicatePointVector(other.group, other.R)),
      c(DuplicateBN(other.c)),
      d(DuplicateBN(other.d)),
      r_h(DuplicateBN(other.r_h))
{
}

SamePermutationArgument::InnerProductProofMessage&
SamePermutationArgument::InnerProductProofMessage::operator=(
    const InnerProductProofMessage& other)
{
    if (this == &other)
    {
        return *this;
    }

    InnerProductProofMessage copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::InnerProductProofMessage::InnerProductProofMessage(
    InnerProductProofMessage&& other) noexcept
    : group(other.group),
      A(other.A),
      B(other.B),
      L(std::move(other.L)),
      R(std::move(other.R)),
      c(other.c),
      d(other.d),
      r_h(other.r_h)
{
    other.group = nullptr;
    other.A = nullptr;
    other.B = nullptr;
    other.c = nullptr;
    other.d = nullptr;
    other.r_h = nullptr;
}

SamePermutationArgument::InnerProductProofMessage&
SamePermutationArgument::InnerProductProofMessage::operator=(
    InnerProductProofMessage&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreePointVector(L);
    FreePointVector(R);
    BN_clear_free(c);
    BN_clear_free(d);
    BN_clear_free(r_h);
    EC_POINT_free(A);
    EC_POINT_free(B);
    group = other.group;
    A = other.A;
    B = other.B;
    L = std::move(other.L);
    R = std::move(other.R);
    c = other.c;
    d = other.d;
    r_h = other.r_h;
    other.group = nullptr;
    other.A = nullptr;
    other.B = nullptr;
    other.c = nullptr;
    other.d = nullptr;
    other.r_h = nullptr;
    return *this;
}

SamePermutationArgument::InnerProductProofMessage::~InnerProductProofMessage()
{
    FreePointVector(L);
    FreePointVector(R);
    BN_clear_free(c);
    BN_clear_free(d);
    BN_clear_free(r_h);
    EC_POINT_free(A);
    EC_POINT_free(B);
}

SamePermutationArgument::ProofMessage::ProofMessage()
{
}

SamePermutationArgument::ProofMessage::ProofMessage(const ProofMessage& other)
    : group(other.group),
      grand_product(other.grand_product),
      inner_product(other.inner_product)
{
}

SamePermutationArgument::ProofMessage&
SamePermutationArgument::ProofMessage::operator=(const ProofMessage& other)
{
    if (this == &other)
    {
        return *this;
    }

    ProofMessage copy(other);
    *this = std::move(copy);
    return *this;
}

SamePermutationArgument::ProofMessage::ProofMessage(
    ProofMessage&& other) noexcept
    : group(other.group),
      grand_product(std::move(other.grand_product)),
      inner_product(std::move(other.inner_product))
{
    other.group = nullptr;
}

SamePermutationArgument::ProofMessage&
SamePermutationArgument::ProofMessage::operator=(ProofMessage&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    group = other.group;
    grand_product = std::move(other.grand_product);
    inner_product = std::move(other.inner_product);
    other.group = nullptr;
    return *this;
}

SamePermutationArgument::ProofMessage::~ProofMessage()
{
}

SamePermutationArgument::SamePermutationArgument(const ElGamalEnc& elgamal)
    : elgamal_(elgamal), bn_ctx_(BN_CTX_new())
{
    ThrowIf(bn_ctx_ == nullptr, "SamePerm BN_CTX allocation failed");
}

SamePermutationArgument::~SamePermutationArgument()
{
    BN_CTX_free(bn_ctx_);
}

void SamePermutationArgument::InitializeSamePermutationProof(
    const std::vector<BIGNUM*>& a,
    const std::vector<std::size_t>& permutation,
    const BIGNUM* r_A,
    const BIGNUM* r_M,
    PublicInstance& public_instance,
    Witness& witness) const
{
    const EC_GROUP* group = elgamal_.Group();
    ThrowIf(
        a.empty() ||
            r_A == nullptr ||
            r_M == nullptr ||
            !IsValidPermutation(permutation, a.size()),
        "SamePerm initialization input is invalid");

    for (const BIGNUM* value : a)
    {
        ThrowIf(
            value == nullptr,
            "SamePerm initialization vector input is invalid");
    }

    PublicInstance next_public;
    next_public.group = group;
    next_public.g.reserve(a.size());
    try
    {
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            EC_POINT* generator = EC_POINT_new(group);
            ThrowIf(generator == nullptr, "SamePerm generator allocation failed");
            elgamal_.GenerateRandomGroupElement(generator);
            next_public.g.emplace_back(generator);
        }
        next_public.h = EC_POINT_new(group);
        ThrowIf(next_public.h == nullptr, "SamePerm h allocation failed");
        elgamal_.GenerateRandomGroupElement(next_public.h);
    }
    catch (...)
    {
        throw;
    }
    next_public.a = DuplicateBNVector(a);
    next_public.n.reserve(a.size());
    next_public.A.group = group;
    next_public.M.group = group;
    next_public.A.value = EC_POINT_new(group);
    next_public.M.value = EC_POINT_new(group);
    next_public.grand_product.group = group;
    next_public.grand_product.g = DuplicatePointVector(group, next_public.g);
    next_public.grand_product.h = DuplicatePoint(group, next_public.h);
    next_public.inner_product.group = group;
    next_public.inner_product.H = EC_POINT_new(group);
    next_public.inner_product.h = EC_POINT_new(group);
    ThrowIf(
        next_public.inner_product.H == nullptr ||
            next_public.inner_product.h == nullptr,
        "SamePerm inner CRS allocation failed");
    elgamal_.GenerateRandomGroupElement(next_public.inner_product.H);
    elgamal_.GenerateRandomGroupElement(next_public.inner_product.h);

    Witness next_witness;
    next_witness.permutation = permutation;
    next_witness.r_A = DuplicateBN(r_A);
    next_witness.r_M = DuplicateBN(r_M);
    next_witness.sigma_a.reserve(a.size());
    next_witness.sigma_n.reserve(a.size());
    try
    {
        for (std::size_t i = 0; i < permutation.size(); ++i)
        {
            BIGNUM* sigma_a_value = DuplicateBN(a[permutation[i]]);
            BIGNUM* sigma_n_value = BN_new();
            BIGNUM* n_value = BN_new();
            ThrowIf(sigma_a_value == nullptr ||
                    sigma_n_value == nullptr ||
                    n_value == nullptr ||
                    BN_set_word(sigma_n_value, static_cast<unsigned long>(permutation[i] + 1)) != 1 ||
                    BN_set_word(n_value, static_cast<unsigned long>(i + 1)) != 1,
                "SamePerm sigma_n allocation failed");
            next_public.n.emplace_back(n_value);
            next_witness.sigma_a.emplace_back(sigma_a_value);
            next_witness.sigma_n.emplace_back(sigma_n_value);
        }
    }
    catch (...)
    {
        throw;
    }

    ThrowIf(
            next_public.h == nullptr ||
            next_public.A.value == nullptr ||
            next_public.M.value == nullptr ||
            next_public.grand_product.h == nullptr ||
            next_witness.r_A == nullptr ||
            next_witness.r_M == nullptr ||
            !VectorCommit(
                next_public.g,
                next_public.h,
                next_witness.sigma_a,
                r_A,
                next_public.A.value) ||
            !VectorCommit(
                next_public.g,
                next_public.h,
                next_witness.sigma_n,
                r_M,
                next_public.M.value),
        "SamePerm public instance computation failed");

    public_instance = std::move(next_public);
    witness = std::move(next_witness);
}

void SamePermutationArgument::CreateSamePermutationProof(
    const PublicInstance& public_instance,
    const Witness& witness,
    Proof& proof) const
{
    ThrowIf(
        !IsValidPublicInstance(public_instance) ||
            !HasMatchingGrandProductGenerators(public_instance) ||
            witness.sigma_a.size() != public_instance.a.size() ||
            witness.sigma_n.size() != public_instance.a.size() ||
            witness.r_A == nullptr ||
            witness.r_M == nullptr ||
            !IsValidPermutation(witness.permutation, public_instance.a.size()),
        "SamePerm proof input is invalid");

    BIGNUM* alpha = BN_new();
    BIGNUM* beta = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* r_B = BN_new();
    BIGNUM* p = BN_new();
    EC_POINT* term = EC_POINT_new(public_instance.group);
    if (alpha == nullptr ||
        beta == nullptr ||
        temp == nullptr ||
        r_B == nullptr ||
        p == nullptr ||
        term == nullptr)
    {
        BN_clear_free(alpha);
        BN_clear_free(beta);
        BN_clear_free(temp);
        BN_clear_free(r_B);
        BN_clear_free(p);
        EC_POINT_free(term);
        ThrowIf(true, "SamePerm proof scalar allocation failed");
    }

    Proof next_proof;
    next_proof.public_instance = public_instance;
    next_proof.witness = witness;
    next_proof.witness.grand_product = GrandProductWitness();
    next_proof.message = ProofMessage();
    next_proof.message.group = public_instance.group;
    next_proof.public_instance.grand_product.B.group = public_instance.group;
    next_proof.public_instance.grand_product.B.value =
        EC_POINT_new(public_instance.group);
    next_proof.public_instance.grand_product.p = p;
    next_proof.witness.grand_product.r_B = r_B;
    next_proof.witness.grand_product.b.reserve(public_instance.a.size());

    try
    {
        ThrowIf(
            next_proof.public_instance.grand_product.h == nullptr ||
                next_proof.public_instance.grand_product.B.value == nullptr,
            "SamePerm proof point allocation failed");

        GenerateSamePermutationChallenges(public_instance, alpha, beta);

        ThrowIf(BN_one(p) != 1, "SamePerm product initialization failed");
        for (std::size_t i = 0; i < witness.sigma_a.size(); ++i)
        {
            BIGNUM* b_value = BN_new();
            ThrowIf(b_value == nullptr, "SamePerm b allocation failed");
            const bool ok =
                BN_copy(b_value, witness.sigma_a[i]) != nullptr &&
                BN_mod_mul(temp, witness.sigma_n[i], alpha, elgamal_.Order(), bn_ctx_) == 1 &&
                BN_mod_add(b_value, b_value, temp, elgamal_.Order(), bn_ctx_) == 1 &&
                BN_mod_add(b_value, b_value, beta, elgamal_.Order(), bn_ctx_) == 1 &&
                BN_mod_mul(p, p, b_value, elgamal_.Order(), bn_ctx_) == 1;
            if (!ok)
            {
                BN_clear_free(b_value);
                ThrowIf(true, "SamePerm b computation failed");
            }
            next_proof.witness.grand_product.b.emplace_back(b_value);
        }

        ThrowIf(
            BN_mod_mul(temp, alpha, witness.r_M, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_add(r_B, witness.r_A, temp, elgamal_.Order(), bn_ctx_) != 1,
            "SamePerm B computation failed");

        ThrowIf(
            EC_POINT_copy(
                next_proof.public_instance.grand_product.B.value,
                public_instance.A.value) != 1 ||
                EC_POINT_mul(
                    public_instance.group,
                    term,
                    nullptr,
                    public_instance.M.value,
                    alpha,
                    bn_ctx_) != 1 ||
                EC_POINT_add(
                    public_instance.group,
                    next_proof.public_instance.grand_product.B.value,
                    next_proof.public_instance.grand_product.B.value,
                    term,
                    bn_ctx_) != 1,
            "SamePerm B computation failed");

        for (const EC_POINT* generator : public_instance.g)
        {
            ThrowIf(
                EC_POINT_mul(
                    public_instance.group,
                    term,
                    nullptr,
                    generator,
                    beta,
                    bn_ctx_) != 1 ||
                    EC_POINT_add(
                        public_instance.group,
                        next_proof.public_instance.grand_product.B.value,
                        next_proof.public_instance.grand_product.B.value,
                        term,
                        bn_ctx_) != 1,
                "SamePerm B computation failed");
        }

        CreateGrandProductProof(
            next_proof.public_instance.grand_product,
            next_proof.witness.grand_product,
            next_proof.public_instance.inner_product,
            next_proof.witness.inner_product,
            next_proof.message.grand_product,
            next_proof.message.inner_product);
    }
    catch (...)
    {
        BN_clear_free(alpha);
        BN_clear_free(beta);
        BN_clear_free(temp);
        EC_POINT_free(term);
        throw;
    }

    proof = std::move(next_proof);

    BN_clear_free(alpha);
    BN_clear_free(beta);
    BN_clear_free(temp);
    EC_POINT_free(term);
}

void SamePermutationArgument::CreateGrandProductProof(
    const GrandProductPublicInstance& public_instance,
    const GrandProductWitness& witness,
    InnerProductPublicInstance& inner_product_public_instance,
    InnerProductWitness& inner_product_witness,
    GrandProductProofMessage& proof_message,
    InnerProductProofMessage& inner_product_proof_message) const
{
    ThrowIf(
        !IsValidGrandProductPublicInstance(public_instance) ||
            inner_product_public_instance.group != public_instance.group ||
            inner_product_public_instance.H == nullptr ||
            inner_product_public_instance.h == nullptr ||
            witness.b.size() != public_instance.g.size() ||
            witness.r_B == nullptr,
        "GrandProduct proof input is invalid");

    BIGNUM* alpha = BN_new();
    BIGNUM* beta = BN_new();
    BIGNUM* r_C = BN_new();
    BIGNUM* r_D = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* beta_power = BN_new();
    BIGNUM* beta_l = nullptr;
    EC_POINT* C = EC_POINT_new(public_instance.group);
    EC_POINT* D = EC_POINT_new(public_instance.group);
    EC_POINT* term = EC_POINT_new(public_instance.group);
    if (alpha == nullptr ||
        beta == nullptr ||
        r_C == nullptr ||
        r_D == nullptr ||
        temp == nullptr ||
        beta_power == nullptr ||
        C == nullptr ||
        D == nullptr ||
        term == nullptr)
    {
        BN_clear_free(alpha);
        BN_clear_free(beta);
        BN_clear_free(r_C);
        BN_clear_free(r_D);
        BN_clear_free(temp);
        BN_clear_free(beta_power);
        EC_POINT_free(C);
        EC_POINT_free(D);
        EC_POINT_free(term);
        ThrowIf(true, "GrandProduct proof allocation failed");
    }

    try
    {
        GenerateGrandProductAlpha(public_instance, alpha);

        InnerProductPublicInstance next_inner_public;
        InnerProductWitness next_inner_witness;
        std::vector<BIGNUM*> c;
        c.reserve(witness.b.size());
        try
        {
            for (std::size_t i = 0; i < witness.b.size(); ++i)
            {
                BIGNUM* value = BN_new();
                ThrowIf(value == nullptr, "GrandProduct c allocation failed");
                bool ok = false;
                if (i == 0)
                {
                    ok = BN_one(value) == 1;
                }
                else
                {
                    ok = BN_copy(value, c.back()) != nullptr &&
                        BN_mod_mul(
                            value,
                            value,
                            witness.b[i - 1],
                            elgamal_.Order(),
                            bn_ctx_) == 1;
                }

                if (!ok)
                {
                    BN_clear_free(value);
                    ThrowIf(true, "GrandProduct c computation failed");
                }
                c.emplace_back(value);
            }

            elgamal_.GenerateRandomScalar(r_C);
            ThrowIf(
                !VectorCommit(public_instance.g, public_instance.h, c, r_C, C) ||
                    BN_mod_add(temp, witness.r_B, alpha, elgamal_.Order(), bn_ctx_) != 1 ||
                    BN_mod_mul(temp, temp, r_C, elgamal_.Order(), bn_ctx_) != 1,
                "GrandProduct C computation failed");

            next_inner_witness.c = DuplicateBNVector(c);
            next_inner_witness.c.emplace_back(DuplicateBN(r_C));
            ThrowIf(
                next_inner_witness.c.back() == nullptr,
                "GrandProduct inner witness allocation failed");
        }
        catch (...)
        {
            FreeBNVector(c);
            throw;
        }
        FreeBNVector(c);

        GrandProductProofMessage next_message;
        next_message.group = public_instance.group;
        next_message.B = DuplicatePoint(public_instance.group, public_instance.B.value);
        next_message.C = DuplicatePoint(public_instance.group, C);
        next_message.r_p = DuplicateBN(temp);
        ThrowIf(
            next_message.B == nullptr ||
                next_message.C == nullptr ||
                next_message.r_p == nullptr,
            "GrandProduct proof message allocation failed");
        GenerateGrandProductBeta(next_message, beta);

        next_inner_public.group = public_instance.group;
        next_inner_public.H = DuplicatePoint(
            public_instance.group,
            inner_product_public_instance.H);
        next_inner_public.h = DuplicatePoint(
            public_instance.group,
            inner_product_public_instance.h);
        ThrowIf(
            next_inner_public.H == nullptr ||
                next_inner_public.h == nullptr,
            "GrandProduct inner CRS allocation failed");
        next_inner_public.C.group = public_instance.group;
        next_inner_public.C.value = DuplicatePoint(public_instance.group, C);
        next_inner_public.D.group = public_instance.group;
        next_inner_public.D.value = D;
        D = nullptr;
        next_inner_public.z = BN_new();
        ThrowIf(
            next_inner_public.H == nullptr ||
                next_inner_public.h == nullptr ||
                next_inner_public.C.value == nullptr ||
                next_inner_public.D.value == nullptr ||
                next_inner_public.z == nullptr,
            "GrandProduct inner public instance allocation failed");

        ThrowIf(BN_one(beta_power) != 1,
            "GrandProduct beta power initialization failed");
        for (std::size_t i = 0; i < public_instance.g.size(); ++i)
        {
            BIGNUM* previous_beta_power = DuplicateBN(beta_power);
            bool ok =
                previous_beta_power != nullptr &&
                BN_mod_mul(
                    beta_power,
                    beta_power,
                    beta,
                    elgamal_.Order(),
                    bn_ctx_) == 1;
            BIGNUM* inverse_power = ok
                ? BN_mod_inverse(nullptr, beta_power, elgamal_.Order(), bn_ctx_)
                : nullptr;
            EC_POINT* g_prime = EC_POINT_new(public_instance.group);
            BIGNUM* b_prime = BN_new();
            BIGNUM* d_value = BN_new();
            ok = ok &&
                inverse_power != nullptr &&
                g_prime != nullptr &&
                b_prime != nullptr &&
                d_value != nullptr &&
                EC_POINT_mul(
                    public_instance.group,
                    g_prime,
                    nullptr,
                    public_instance.g[i],
                    inverse_power,
                    bn_ctx_) == 1 &&
                BN_mod_mul(
                    b_prime,
                    witness.b[i],
                    beta_power,
                    elgamal_.Order(),
                    bn_ctx_) == 1 &&
                BN_mod_sub(
                    d_value,
                    b_prime,
                    previous_beta_power,
                    elgamal_.Order(),
                    bn_ctx_) == 1;
            BN_clear_free(inverse_power);
            BN_clear_free(previous_beta_power);
            BN_clear_free(b_prime);
            if (!ok)
            {
                EC_POINT_free(g_prime);
                BN_clear_free(d_value);
                ThrowIf(true, "GrandProduct transformed vector computation failed");
            }

            next_inner_public.G.emplace_back(DuplicatePoint(
                public_instance.group,
                public_instance.g[i]));
            next_inner_public.G_prime.emplace_back(g_prime);
            next_inner_witness.d.emplace_back(d_value);
            ThrowIf(
                next_inner_public.G.back() == nullptr,
                "GrandProduct G allocation failed");
        }

        ThrowIf(
            BN_mod_mul(
                beta_power,
                beta_power,
                beta,
                elgamal_.Order(),
                bn_ctx_) != 1,
            "GrandProduct beta final power computation failed");

        BIGNUM* h_prime_scalar =
            BN_mod_inverse(nullptr, beta_power, elgamal_.Order(), bn_ctx_);
        EC_POINT* h_prime = EC_POINT_new(public_instance.group);
        ThrowIf(
            h_prime_scalar == nullptr ||
                h_prime == nullptr ||
                EC_POINT_mul(
                    public_instance.group,
                    h_prime,
                    nullptr,
                    public_instance.h,
                    h_prime_scalar,
                    bn_ctx_) != 1,
            "GrandProduct h_prime computation failed");
        BN_clear_free(h_prime_scalar);
        next_inner_public.G.emplace_back(DuplicatePoint(public_instance.group, public_instance.h));
        next_inner_public.G_prime.emplace_back(h_prime);
        ThrowIf(next_inner_public.G.back() == nullptr, "GrandProduct H vector allocation failed");

        ThrowIf(
            BN_mod_add(temp, witness.r_B, alpha, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_mul(r_D, beta_power, temp, elgamal_.Order(), bn_ctx_) != 1,
            "GrandProduct r_D computation failed");
        next_inner_witness.d.emplace_back(DuplicateBN(r_D));
        ThrowIf(
            next_inner_witness.d.back() == nullptr,
            "GrandProduct inner d witness allocation failed");

        ThrowIf(
            EC_POINT_copy(next_inner_public.D.value, public_instance.B.value) != 1,
            "GrandProduct D initialization failed");
        ThrowIf(BN_one(beta_power) != 1,
            "GrandProduct D beta power initialization failed");
        for (std::size_t i = 0; i < public_instance.g.size(); ++i)
        {
            ThrowIf(
                EC_POINT_mul(
                    public_instance.group,
                    term,
                    nullptr,
                    next_inner_public.G_prime[i],
                    beta_power,
                    bn_ctx_) != 1 ||
                    EC_POINT_invert(public_instance.group, term, bn_ctx_) != 1 ||
                    EC_POINT_add(
                        public_instance.group,
                        next_inner_public.D.value,
                        next_inner_public.D.value,
                        term,
                        bn_ctx_) != 1 ||
                    BN_mod_mul(
                        beta_power,
                        beta_power,
                        beta,
                        elgamal_.Order(),
                        bn_ctx_) != 1,
                "GrandProduct D computation failed");
        }
        beta_l = DuplicateBN(beta_power);
        ThrowIf(
            beta_l == nullptr ||
            BN_mod_mul(
                beta_power,
                beta_power,
                beta,
                elgamal_.Order(),
                bn_ctx_) != 1 ||
            BN_mod_mul(
                temp,
                alpha,
                beta_power,
                elgamal_.Order(),
                bn_ctx_) != 1 ||
                EC_POINT_mul(
                    public_instance.group,
                    term,
                    nullptr,
                    next_inner_public.G_prime.back(),
                    temp,
                    bn_ctx_) != 1 ||
                EC_POINT_add(
                    public_instance.group,
                    next_inner_public.D.value,
                    next_inner_public.D.value,
                    term,
                    bn_ctx_) != 1,
            "GrandProduct D final term computation failed");

        ThrowIf(
            BN_mod_mul(
                next_inner_public.z,
                public_instance.p,
                beta_l,
                elgamal_.Order(),
                bn_ctx_) != 1 ||
                BN_mod_mul(temp, next_message.r_p, beta_power, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_add(
                    next_inner_public.z,
                    next_inner_public.z,
                    temp,
                    elgamal_.Order(),
                    bn_ctx_) != 1 ||
                BN_sub_word(next_inner_public.z, 1) != 1 ||
                BN_nnmod(
                    next_inner_public.z,
                    next_inner_public.z,
                    elgamal_.Order(),
                    bn_ctx_) != 1,
            "GrandProduct z computation failed");
        BN_clear_free(beta_l);
        beta_l = nullptr;

        inner_product_public_instance = std::move(next_inner_public);
        inner_product_witness = std::move(next_inner_witness);
        proof_message = std::move(next_message);
        CreateInnerProductProof(
            inner_product_public_instance,
            inner_product_witness,
            inner_product_proof_message);
    }
    catch (...)
    {
        BN_clear_free(alpha);
        BN_clear_free(beta);
        BN_clear_free(r_C);
        BN_clear_free(r_D);
        BN_clear_free(temp);
        BN_clear_free(beta_power);
        BN_clear_free(beta_l);
        EC_POINT_free(C);
        EC_POINT_free(D);
        EC_POINT_free(term);
        throw;
    }

    BN_clear_free(alpha);
    BN_clear_free(beta);
    BN_clear_free(r_C);
    BN_clear_free(r_D);
    BN_clear_free(temp);
    BN_clear_free(beta_power);
    BN_clear_free(beta_l);
    EC_POINT_free(C);
    EC_POINT_free(D);
    EC_POINT_free(term);
}

bool SamePermutationArgument::VerifyGrandProductProof(
    const GrandProductPublicInstance& public_instance,
    const InnerProductPublicInstance& inner_product_public_instance,
    const GrandProductProofMessage& proof_message,
    const InnerProductProofMessage& inner_product_proof_message) const
{
    if (!IsValidGrandProductPublicInstance(public_instance) ||
        inner_product_public_instance.group != public_instance.group ||
        inner_product_public_instance.G.size() != public_instance.g.size() + 1 ||
        inner_product_public_instance.G_prime.size() != public_instance.g.size() + 1 ||
        proof_message.group != public_instance.group ||
        proof_message.B == nullptr ||
        proof_message.C == nullptr ||
        proof_message.r_p == nullptr ||
        EC_POINT_is_on_curve(public_instance.group, proof_message.B, bn_ctx_) != 1 ||
        EC_POINT_is_on_curve(public_instance.group, proof_message.C, bn_ctx_) != 1 ||
        EC_POINT_cmp(
            public_instance.group,
            proof_message.B,
            public_instance.B.value,
            bn_ctx_) != 0 ||
        inner_product_public_instance.H == nullptr ||
        inner_product_public_instance.h == nullptr ||
        EC_POINT_is_on_curve(
            public_instance.group,
            inner_product_public_instance.H,
            bn_ctx_) != 1 ||
        EC_POINT_is_on_curve(
            public_instance.group,
            inner_product_public_instance.h,
            bn_ctx_) != 1)
    {
        return false;
    }

    BIGNUM* alpha = BN_new();
    BIGNUM* beta = BN_new();
    BIGNUM* beta_power = BN_new();
    BIGNUM* beta_l = nullptr;
    BIGNUM* temp = BN_new();
    EC_POINT* D = EC_POINT_new(public_instance.group);
    EC_POINT* term = EC_POINT_new(public_instance.group);
    if (alpha == nullptr ||
        beta == nullptr ||
        beta_power == nullptr ||
        temp == nullptr ||
        D == nullptr ||
        term == nullptr)
    {
        BN_clear_free(alpha);
        BN_clear_free(beta);
        BN_clear_free(beta_power);
        BN_clear_free(temp);
        EC_POINT_free(D);
        EC_POINT_free(term);
        return false;
    }

    bool ok = true;
    GenerateGrandProductAlpha(public_instance, alpha);
    GenerateGrandProductBeta(proof_message, beta);

    ok =
        inner_product_public_instance.C.value != nullptr &&
        inner_product_public_instance.D.value != nullptr &&
        inner_product_public_instance.z != nullptr &&
        EC_POINT_cmp(
            public_instance.group,
            inner_product_public_instance.C.value,
            proof_message.C,
            bn_ctx_) == 0;

    ok = ok && BN_one(beta_power) == 1;
    for (std::size_t i = 0; ok && i < public_instance.g.size(); ++i)
    {
        ok = BN_mod_mul(
            beta_power,
            beta_power,
            beta,
            elgamal_.Order(),
            bn_ctx_) == 1;
        BIGNUM* inverse_power = ok
            ? BN_mod_inverse(nullptr, beta_power, elgamal_.Order(), bn_ctx_)
            : nullptr;
        EC_POINT* g_prime = EC_POINT_new(public_instance.group);
        ok = ok &&
            inverse_power != nullptr &&
            g_prime != nullptr &&
            EC_POINT_mul(
                public_instance.group,
                g_prime,
                nullptr,
                public_instance.g[i],
                inverse_power,
                bn_ctx_) == 1 &&
            inner_product_public_instance.G[i] != nullptr &&
            inner_product_public_instance.G_prime[i] != nullptr &&
            EC_POINT_cmp(
                public_instance.group,
                inner_product_public_instance.G[i],
                public_instance.g[i],
                bn_ctx_) == 0 &&
            EC_POINT_cmp(
                public_instance.group,
                inner_product_public_instance.G_prime[i],
                g_prime,
                bn_ctx_) == 0;
        BN_clear_free(inverse_power);
        EC_POINT_free(g_prime);
    }

    ok = ok &&
        BN_mod_mul(beta_power, beta_power, beta, elgamal_.Order(), bn_ctx_) == 1;
    BIGNUM* h_prime_scalar = ok
        ? BN_mod_inverse(nullptr, beta_power, elgamal_.Order(), bn_ctx_)
        : nullptr;
    EC_POINT* h_prime = EC_POINT_new(public_instance.group);
    ok = ok &&
        h_prime_scalar != nullptr &&
        h_prime != nullptr &&
            EC_POINT_mul(
                public_instance.group,
                h_prime,
                nullptr,
                public_instance.h,
                h_prime_scalar,
                bn_ctx_) == 1 &&
            inner_product_public_instance.G.back() != nullptr &&
            inner_product_public_instance.G_prime.back() != nullptr &&
            EC_POINT_cmp(
                public_instance.group,
                inner_product_public_instance.G.back(),
                public_instance.h,
                bn_ctx_) == 0 &&
            EC_POINT_cmp(
                public_instance.group,
                inner_product_public_instance.G_prime.back(),
                h_prime,
                bn_ctx_) == 0;
    BN_clear_free(h_prime_scalar);
    EC_POINT_free(h_prime);

    ok = ok &&
        EC_POINT_copy(D, public_instance.B.value) == 1 &&
        BN_one(beta_power) == 1;
    for (std::size_t i = 0; ok && i < public_instance.g.size(); ++i)
    {
        ok =
            EC_POINT_mul(
                public_instance.group,
                term,
                nullptr,
                inner_product_public_instance.G_prime[i],
                beta_power,
                bn_ctx_) == 1 &&
            EC_POINT_invert(public_instance.group, term, bn_ctx_) == 1 &&
            EC_POINT_add(
                public_instance.group,
                D,
                D,
                term,
                bn_ctx_) == 1 &&
            BN_mod_mul(
                beta_power,
                beta_power,
                beta,
                elgamal_.Order(),
                bn_ctx_) == 1;
    }

    beta_l = DuplicateBN(beta_power);
    ok = ok &&
        beta_l != nullptr &&
        BN_mod_mul(beta_power, beta_power, beta, elgamal_.Order(), bn_ctx_) == 1 &&
        BN_mod_mul(temp, alpha, beta_power, elgamal_.Order(), bn_ctx_) == 1 &&
        EC_POINT_mul(
            public_instance.group,
            term,
            nullptr,
            inner_product_public_instance.G_prime.back(),
            temp,
            bn_ctx_) == 1 &&
        EC_POINT_add(
            public_instance.group,
            D,
            D,
            term,
            bn_ctx_) == 1;

    ok = ok &&
        EC_POINT_cmp(
            public_instance.group,
            inner_product_public_instance.D.value,
            D,
            bn_ctx_) == 0 &&
        BN_mod_mul(
            temp,
            public_instance.p,
            beta_l,
            elgamal_.Order(),
            bn_ctx_) == 1 &&
        BN_mod_mul(beta_l, proof_message.r_p, beta_power, elgamal_.Order(), bn_ctx_) == 1 &&
        BN_mod_add(
            temp,
            temp,
            beta_l,
            elgamal_.Order(),
            bn_ctx_) == 1 &&
        BN_sub_word(temp, 1) == 1 &&
        BN_nnmod(temp, temp, elgamal_.Order(), bn_ctx_) == 1 &&
        BN_cmp(inner_product_public_instance.z, temp) == 0 &&
        VerifyInnerProductProof(
            inner_product_public_instance,
            inner_product_proof_message);

    BN_clear_free(alpha);
    BN_clear_free(beta);
    BN_clear_free(beta_power);
    BN_clear_free(beta_l);
    BN_clear_free(temp);
    EC_POINT_free(D);
    EC_POINT_free(term);
    return ok;
}

void SamePermutationArgument::CreateInnerProductProof(
    const InnerProductPublicInstance& public_instance,
    const InnerProductWitness& witness,
    InnerProductProofMessage& proof_message) const
{
    ThrowIf(
        public_instance.group != elgamal_.Group() ||
            public_instance.G.empty() ||
            public_instance.G.size() != public_instance.G_prime.size() ||
            public_instance.G.size() != witness.c.size() ||
            witness.c.size() != witness.d.size() ||
            public_instance.H == nullptr ||
            public_instance.h == nullptr ||
            public_instance.C.group != public_instance.group ||
            public_instance.D.group != public_instance.group ||
            public_instance.C.value == nullptr ||
            public_instance.D.value == nullptr ||
            public_instance.z == nullptr ||
            EC_POINT_is_on_curve(public_instance.group, public_instance.H, bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(public_instance.group, public_instance.h, bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(public_instance.group, public_instance.C.value, bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(public_instance.group, public_instance.D.value, bn_ctx_) != 1,
        "InnerProduct proof input is invalid");
    ThrowIf(!IsPowerOfTwo(public_instance.G.size()),
        "InnerProduct proof vector size must be a power of two");
    for (std::size_t i = 0; i < public_instance.G.size(); ++i)
    {
        ThrowIf(
            public_instance.G[i] == nullptr ||
                public_instance.G_prime[i] == nullptr ||
                witness.c[i] == nullptr ||
                witness.d[i] == nullptr ||
                EC_POINT_is_on_curve(public_instance.group, public_instance.G[i], bn_ctx_) != 1 ||
                EC_POINT_is_on_curve(
                    public_instance.group,
                    public_instance.G_prime[i],
                    bn_ctx_) != 1,
            "InnerProduct proof vector input is invalid");
    }

    std::vector<EC_POINT*> G = DuplicatePointVector(public_instance.group, public_instance.G);
    std::vector<EC_POINT*> G_prime =
        DuplicatePointVector(public_instance.group, public_instance.G_prime);
    std::vector<BIGNUM*> c = DuplicateBNVector(witness.c);
    std::vector<BIGNUM*> d = DuplicateBNVector(witness.d);

    BIGNUM* beta = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* gamma = BN_new();
    BIGNUM* gamma_inverse = nullptr;
    BIGNUM* gamma_square = BN_new();
    BIGNUM* inverse_square = BN_new();
    BIGNUM* scalar = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* r_h = BN_new();
    BIGNUM* r_L = BN_new();
    BIGNUM* r_R = BN_new();
    BIGNUM* r_C = BN_new();
    BIGNUM* r_D = BN_new();
    BIGNUM* r_hr = BN_new();
    BIGNUM* r_rh = BN_new();
    BIGNUM* alpha = BN_new();
    BIGNUM* alpha_square = BN_new();
    EC_POINT* H = DuplicatePoint(public_instance.group, public_instance.H);
    EC_POINT* h = DuplicatePoint(public_instance.group, public_instance.h);
    EC_POINT* term = EC_POINT_new(public_instance.group);
    EC_POINT* L = nullptr;
    EC_POINT* R = nullptr;
    EC_POINT* A = EC_POINT_new(public_instance.group);
    EC_POINT* B = EC_POINT_new(public_instance.group);
    if (beta == nullptr ||
        e == nullptr ||
        gamma == nullptr ||
        gamma_square == nullptr ||
        inverse_square == nullptr ||
        scalar == nullptr ||
        temp == nullptr ||
        r_h == nullptr ||
        r_L == nullptr ||
        r_R == nullptr ||
        r_C == nullptr ||
        r_D == nullptr ||
        r_hr == nullptr ||
        r_rh == nullptr ||
        alpha == nullptr ||
        alpha_square == nullptr ||
        H == nullptr ||
        h == nullptr ||
        term == nullptr ||
        A == nullptr ||
        B == nullptr)
    {
        FreePointVector(G);
        FreePointVector(G_prime);
        FreeBNVector(c);
        FreeBNVector(d);
        BN_clear_free(beta);
        BN_clear_free(e);
        BN_clear_free(gamma);
        BN_clear_free(gamma_square);
        BN_clear_free(inverse_square);
        BN_clear_free(scalar);
        BN_clear_free(temp);
        BN_clear_free(r_h);
        BN_clear_free(r_L);
        BN_clear_free(r_R);
        BN_clear_free(r_C);
        BN_clear_free(r_D);
        BN_clear_free(r_hr);
        BN_clear_free(r_rh);
        BN_clear_free(alpha);
        BN_clear_free(alpha_square);
        EC_POINT_free(H);
        EC_POINT_free(h);
        EC_POINT_free(term);
        EC_POINT_free(A);
        EC_POINT_free(B);
        ThrowIf(true, "InnerProduct proof allocation failed");
    }

    auto add_scaled_point = [&](EC_POINT* target, const EC_POINT* point, const BIGNUM* value)
    {
        return EC_POINT_mul(public_instance.group, term, nullptr, point, value, bn_ctx_) == 1 &&
            EC_POINT_add(public_instance.group, target, target, term, bn_ctx_) == 1;
    };

    try
    {
        GenerateInnerProductChallenges(public_instance, beta, e);
        ThrowIf(
            EC_POINT_mul(public_instance.group, term, nullptr, H, beta, bn_ctx_) != 1 ||
                EC_POINT_copy(H, term) != 1 ||
                EC_POINT_mul(public_instance.group, term, nullptr, h, e, bn_ctx_) != 1 ||
                EC_POINT_copy(h, term) != 1 ||
                BN_set_word(r_h, 0) != 1,
            "InnerProduct challenge preparation failed");

        InnerProductProofMessage next_message;
        next_message.group = public_instance.group;
        while (G.size() > 1)
        {
            const std::size_t half = G.size() / 2;
            L = EC_POINT_new(public_instance.group);
            R = EC_POINT_new(public_instance.group);
            ThrowIf(L == nullptr || R == nullptr, "InnerProduct round point allocation failed");
            ThrowIf(
                EC_POINT_set_to_infinity(public_instance.group, L) != 1 ||
                    EC_POINT_set_to_infinity(public_instance.group, R) != 1,
                "InnerProduct round point initialization failed");

            elgamal_.GenerateRandomScalar(r_L);
            elgamal_.GenerateRandomScalar(r_R);

            BIGNUM* cross_left = BN_new();
            BIGNUM* cross_right = BN_new();
            ThrowIf(cross_left == nullptr || cross_right == nullptr,
                "InnerProduct cross term allocation failed");
            try
            {
                ThrowIf(BN_set_word(cross_left, 0) != 1 ||
                        BN_set_word(cross_right, 0) != 1,
                    "InnerProduct cross term initialization failed");
                for (std::size_t i = 0; i < half; ++i)
                {
                    ThrowIf(
                        !add_scaled_point(L, G[half + i], c[i]) ||
                            !add_scaled_point(L, G_prime[i], d[half + i]) ||
                            BN_mod_mul(temp, c[i], d[half + i], elgamal_.Order(), bn_ctx_) != 1 ||
                            BN_mod_add(cross_left, cross_left, temp, elgamal_.Order(), bn_ctx_) != 1 ||
                            !add_scaled_point(R, G[i], c[half + i]) ||
                            !add_scaled_point(R, G_prime[half + i], d[i]) ||
                            BN_mod_mul(temp, c[half + i], d[i], elgamal_.Order(), bn_ctx_) != 1 ||
                            BN_mod_add(cross_right, cross_right, temp, elgamal_.Order(), bn_ctx_) != 1,
                        "InnerProduct round vector computation failed");
                }

                ThrowIf(
                    !add_scaled_point(L, H, cross_left) ||
                        !add_scaled_point(L, h, r_L) ||
                        !add_scaled_point(R, H, cross_right) ||
                        !add_scaled_point(R, h, r_R),
                    "InnerProduct round commitment computation failed");
            }
            catch (...)
            {
                BN_clear_free(cross_left);
                BN_clear_free(cross_right);
                throw;
            }
            BN_clear_free(cross_left);
            BN_clear_free(cross_right);

            GenerateInnerProductRoundChallenge(L, R, gamma);
            gamma_inverse = BN_mod_inverse(nullptr, gamma, elgamal_.Order(), bn_ctx_);
            ThrowIf(gamma_inverse == nullptr, "InnerProduct gamma inverse failed");
            ThrowIf(
                BN_mod_sqr(gamma_square, gamma, elgamal_.Order(), bn_ctx_) != 1 ||
                    BN_mod_sqr(
                        inverse_square,
                        gamma_inverse,
                        elgamal_.Order(),
                        bn_ctx_) != 1,
                "InnerProduct gamma square computation failed");

            std::vector<BIGNUM*> next_c;
            std::vector<BIGNUM*> next_d;
            std::vector<EC_POINT*> next_G;
            std::vector<EC_POINT*> next_G_prime;
            next_c.reserve(half);
            next_d.reserve(half);
            next_G.reserve(half);
            next_G_prime.reserve(half);
            try
            {
                for (std::size_t i = 0; i < half; ++i)
                {
                    BIGNUM* c_value = BN_new();
                    BIGNUM* d_value = BN_new();
                    EC_POINT* G_value = EC_POINT_new(public_instance.group);
                    EC_POINT* G_prime_value = EC_POINT_new(public_instance.group);
                    ThrowIf(
                        c_value == nullptr ||
                            d_value == nullptr ||
                            G_value == nullptr ||
                            G_prime_value == nullptr,
                        "InnerProduct folded vector allocation failed");

                    const bool ok =
                        BN_mod_mul(c_value, gamma, c[i], elgamal_.Order(), bn_ctx_) == 1 &&
                        BN_mod_mul(temp, gamma_inverse, c[half + i], elgamal_.Order(), bn_ctx_) == 1 &&
                        BN_mod_add(c_value, c_value, temp, elgamal_.Order(), bn_ctx_) == 1 &&
                        BN_mod_mul(d_value, gamma_inverse, d[i], elgamal_.Order(), bn_ctx_) == 1 &&
                        BN_mod_mul(temp, gamma, d[half + i], elgamal_.Order(), bn_ctx_) == 1 &&
                        BN_mod_add(d_value, d_value, temp, elgamal_.Order(), bn_ctx_) == 1 &&
                        EC_POINT_mul(
                            public_instance.group,
                            G_value,
                            nullptr,
                            G[i],
                            gamma_inverse,
                            bn_ctx_) == 1 &&
                        EC_POINT_mul(
                            public_instance.group,
                            term,
                            nullptr,
                            G[half + i],
                            gamma,
                            bn_ctx_) == 1 &&
                        EC_POINT_add(
                            public_instance.group,
                            G_value,
                            G_value,
                            term,
                            bn_ctx_) == 1 &&
                        EC_POINT_mul(
                            public_instance.group,
                            G_prime_value,
                            nullptr,
                            G_prime[i],
                            gamma,
                            bn_ctx_) == 1 &&
                        EC_POINT_mul(
                            public_instance.group,
                            term,
                            nullptr,
                            G_prime[half + i],
                            gamma_inverse,
                            bn_ctx_) == 1 &&
                        EC_POINT_add(
                            public_instance.group,
                            G_prime_value,
                            G_prime_value,
                            term,
                            bn_ctx_) == 1;
                    if (!ok)
                    {
                        BN_clear_free(c_value);
                        BN_clear_free(d_value);
                        EC_POINT_free(G_value);
                        EC_POINT_free(G_prime_value);
                        ThrowIf(true, "InnerProduct folded vector computation failed");
                    }

                    next_c.emplace_back(c_value);
                    next_d.emplace_back(d_value);
                    next_G.emplace_back(G_value);
                    next_G_prime.emplace_back(G_prime_value);
                }
            }
            catch (...)
            {
                FreeBNVector(next_c);
                FreeBNVector(next_d);
                FreePointVector(next_G);
                FreePointVector(next_G_prime);
                throw;
            }

            ThrowIf(
                BN_mod_mul(temp, r_L, gamma_square, elgamal_.Order(), bn_ctx_) != 1 ||
                    BN_mod_add(r_h, r_h, temp, elgamal_.Order(), bn_ctx_) != 1 ||
                    BN_mod_mul(temp, r_R, inverse_square, elgamal_.Order(), bn_ctx_) != 1 ||
                    BN_mod_add(r_h, r_h, temp, elgamal_.Order(), bn_ctx_) != 1,
                "InnerProduct r_h folding failed");

            next_message.L.emplace_back(L);
            next_message.R.emplace_back(R);
            L = nullptr;
            R = nullptr;
            FreeBNVector(c);
            FreeBNVector(d);
            FreePointVector(G);
            FreePointVector(G_prime);
            c = std::move(next_c);
            d = std::move(next_d);
            G = std::move(next_G);
            G_prime = std::move(next_G_prime);
            BN_clear_free(gamma_inverse);
            gamma_inverse = nullptr;
        }

        elgamal_.GenerateRandomScalar(r_C);
        elgamal_.GenerateRandomScalar(r_D);
        elgamal_.GenerateRandomScalar(r_hr);
        elgamal_.GenerateRandomScalar(r_rh);
        ThrowIf(
            EC_POINT_set_to_infinity(public_instance.group, A) != 1 ||
                EC_POINT_set_to_infinity(public_instance.group, B) != 1 ||
                !add_scaled_point(A, G[0], r_C) ||
                !add_scaled_point(A, G_prime[0], r_D) ||
                BN_mod_mul(scalar, r_C, d[0], elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_mul(temp, r_D, c[0], elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_add(scalar, scalar, temp, elgamal_.Order(), bn_ctx_) != 1 ||
                !add_scaled_point(A, H, scalar) ||
                !add_scaled_point(A, h, r_hr) ||
                BN_mod_mul(scalar, r_C, r_D, elgamal_.Order(), bn_ctx_) != 1 ||
                !add_scaled_point(B, H, scalar) ||
                !add_scaled_point(B, h, r_rh),
            "InnerProduct final commitment computation failed");

        next_message.A = A;
        next_message.B = B;
        A = nullptr;
        B = nullptr;
        GenerateInnerProductAlpha(public_instance, next_message, alpha);
        ThrowIf(
            BN_mod_sqr(alpha_square, alpha, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_mul(temp, alpha, c[0], elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_add(next_message.c, r_C, temp, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_mul(temp, alpha, d[0], elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_add(next_message.d, r_D, temp, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_mul(next_message.r_h, alpha_square, r_h, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_mul(temp, alpha, r_hr, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_add(next_message.r_h, next_message.r_h, temp, elgamal_.Order(), bn_ctx_) != 1 ||
                BN_mod_add(next_message.r_h, next_message.r_h, r_rh, elgamal_.Order(), bn_ctx_) != 1,
            "InnerProduct final response computation failed");

        proof_message = std::move(next_message);
    }
    catch (...)
    {
        FreePointVector(G);
        FreePointVector(G_prime);
        FreeBNVector(c);
        FreeBNVector(d);
        BN_clear_free(beta);
        BN_clear_free(e);
        BN_clear_free(gamma);
        BN_clear_free(gamma_inverse);
        BN_clear_free(gamma_square);
        BN_clear_free(inverse_square);
        BN_clear_free(scalar);
        BN_clear_free(temp);
        BN_clear_free(r_h);
        BN_clear_free(r_L);
        BN_clear_free(r_R);
        BN_clear_free(r_C);
        BN_clear_free(r_D);
        BN_clear_free(r_hr);
        BN_clear_free(r_rh);
        BN_clear_free(alpha);
        BN_clear_free(alpha_square);
        EC_POINT_free(H);
        EC_POINT_free(h);
        EC_POINT_free(term);
        EC_POINT_free(L);
        EC_POINT_free(R);
        EC_POINT_free(A);
        EC_POINT_free(B);
        throw;
    }

    FreePointVector(G);
    FreePointVector(G_prime);
    FreeBNVector(c);
    FreeBNVector(d);
    BN_clear_free(beta);
    BN_clear_free(e);
    BN_clear_free(gamma);
    BN_clear_free(gamma_inverse);
    BN_clear_free(gamma_square);
    BN_clear_free(inverse_square);
    BN_clear_free(scalar);
    BN_clear_free(temp);
    BN_clear_free(r_h);
    BN_clear_free(r_L);
    BN_clear_free(r_R);
    BN_clear_free(r_C);
    BN_clear_free(r_D);
    BN_clear_free(r_hr);
    BN_clear_free(r_rh);
    BN_clear_free(alpha);
    BN_clear_free(alpha_square);
    EC_POINT_free(H);
    EC_POINT_free(h);
    EC_POINT_free(term);
    EC_POINT_free(A);
    EC_POINT_free(B);
}

bool SamePermutationArgument::VerifyInnerProductProof(
    const InnerProductPublicInstance& public_instance,
    const InnerProductProofMessage& proof_message) const
{
    if (!(public_instance.group == elgamal_.Group() &&
        !public_instance.G.empty() &&
        IsPowerOfTwo(public_instance.G.size()) &&
        public_instance.G.size() == public_instance.G_prime.size() &&
        public_instance.H != nullptr &&
        public_instance.h != nullptr &&
        public_instance.C.group == public_instance.group &&
        public_instance.D.group == public_instance.group &&
        public_instance.C.value != nullptr &&
        public_instance.D.value != nullptr &&
        public_instance.z != nullptr &&
        EC_POINT_is_on_curve(public_instance.group, public_instance.H, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(public_instance.group, public_instance.h, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(public_instance.group, public_instance.C.value, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(public_instance.group, public_instance.D.value, bn_ctx_) == 1 &&
        proof_message.group == public_instance.group &&
        proof_message.A != nullptr &&
        proof_message.B != nullptr &&
        proof_message.c != nullptr &&
        proof_message.d != nullptr &&
        proof_message.r_h != nullptr &&
        proof_message.L.size() == proof_message.R.size() &&
        EC_POINT_is_on_curve(public_instance.group, proof_message.A, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(public_instance.group, proof_message.B, bn_ctx_) == 1))
    {
        return false;
    }
    for (std::size_t i = 0; i < public_instance.G.size(); ++i)
    {
        if (public_instance.G[i] == nullptr ||
            public_instance.G_prime[i] == nullptr ||
            EC_POINT_is_on_curve(public_instance.group, public_instance.G[i], bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(
                public_instance.group,
                public_instance.G_prime[i],
                bn_ctx_) != 1)
        {
            return false;
        }
    }

    std::vector<EC_POINT*> G = DuplicatePointVector(public_instance.group, public_instance.G);
    std::vector<EC_POINT*> G_prime =
        DuplicatePointVector(public_instance.group, public_instance.G_prime);
    BIGNUM* beta = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* gamma = BN_new();
    BIGNUM* gamma_inverse = nullptr;
    BIGNUM* gamma_square = BN_new();
    BIGNUM* inverse_square = BN_new();
    BIGNUM* alpha = BN_new();
    BIGNUM* alpha_square = BN_new();
    BIGNUM* scalar = BN_new();
    BIGNUM* temp = BN_new();
    EC_POINT* H = DuplicatePoint(public_instance.group, public_instance.H);
    EC_POINT* h = DuplicatePoint(public_instance.group, public_instance.h);
    EC_POINT* P = EC_POINT_new(public_instance.group);
    EC_POINT* rhs = EC_POINT_new(public_instance.group);
    EC_POINT* term = EC_POINT_new(public_instance.group);
    EC_POINT* next_point = nullptr;
    if (beta == nullptr ||
        e == nullptr ||
        gamma == nullptr ||
        gamma_square == nullptr ||
        inverse_square == nullptr ||
        alpha == nullptr ||
        alpha_square == nullptr ||
        scalar == nullptr ||
        temp == nullptr ||
        H == nullptr ||
        h == nullptr ||
        P == nullptr ||
        rhs == nullptr ||
        term == nullptr)
    {
        FreePointVector(G);
        FreePointVector(G_prime);
        BN_clear_free(beta);
        BN_clear_free(e);
        BN_clear_free(gamma);
        BN_clear_free(gamma_square);
        BN_clear_free(inverse_square);
        BN_clear_free(alpha);
        BN_clear_free(alpha_square);
        BN_clear_free(scalar);
        BN_clear_free(temp);
        EC_POINT_free(H);
        EC_POINT_free(h);
        EC_POINT_free(P);
        EC_POINT_free(rhs);
        EC_POINT_free(term);
        return false;
    }

    auto add_scaled_point = [&](EC_POINT* target, const EC_POINT* point, const BIGNUM* value)
    {
        return EC_POINT_mul(public_instance.group, term, nullptr, point, value, bn_ctx_) == 1 &&
            EC_POINT_add(public_instance.group, target, target, term, bn_ctx_) == 1;
    };

    bool ok = true;
    GenerateInnerProductChallenges(public_instance, beta, e);
    ok =
        EC_POINT_mul(public_instance.group, term, nullptr, H, beta, bn_ctx_) == 1 &&
        EC_POINT_copy(H, term) == 1 &&
        EC_POINT_mul(public_instance.group, term, nullptr, h, e, bn_ctx_) == 1 &&
        EC_POINT_copy(h, term) == 1 &&
        EC_POINT_copy(P, public_instance.C.value) == 1 &&
        EC_POINT_add(public_instance.group, P, P, public_instance.D.value, bn_ctx_) == 1 &&
        add_scaled_point(P, H, public_instance.z);

    std::size_t round = 0;
    while (ok && G.size() > 1)
    {
        if (round >= proof_message.L.size() ||
            proof_message.L[round] == nullptr ||
            proof_message.R[round] == nullptr ||
            EC_POINT_is_on_curve(public_instance.group, proof_message.L[round], bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(public_instance.group, proof_message.R[round], bn_ctx_) != 1)
        {
            ok = false;
            break;
        }

        GenerateInnerProductRoundChallenge(
            proof_message.L[round],
            proof_message.R[round],
            gamma);
        gamma_inverse = BN_mod_inverse(nullptr, gamma, elgamal_.Order(), bn_ctx_);
        ok =
            gamma_inverse != nullptr &&
            BN_mod_sqr(gamma_square, gamma, elgamal_.Order(), bn_ctx_) == 1 &&
            BN_mod_sqr(inverse_square, gamma_inverse, elgamal_.Order(), bn_ctx_) == 1 &&
            add_scaled_point(P, proof_message.L[round], gamma_square) &&
            add_scaled_point(P, proof_message.R[round], inverse_square);
        BN_clear_free(gamma_inverse);
        gamma_inverse = nullptr;
        if (!ok)
        {
            break;
        }

        const std::size_t half = G.size() / 2;
        std::vector<EC_POINT*> next_G;
        std::vector<EC_POINT*> next_G_prime;
        next_G.reserve(half);
        next_G_prime.reserve(half);
        try
        {
            gamma_inverse = BN_mod_inverse(nullptr, gamma, elgamal_.Order(), bn_ctx_);
            ThrowIf(gamma_inverse == nullptr, "InnerProduct verify gamma inverse failed");
            for (std::size_t i = 0; i < half; ++i)
            {
                EC_POINT* G_value = EC_POINT_new(public_instance.group);
                EC_POINT* G_prime_value = EC_POINT_new(public_instance.group);
                ThrowIf(
                    G_value == nullptr || G_prime_value == nullptr,
                    "InnerProduct verify folded point allocation failed");
                const bool folded_ok =
                    EC_POINT_mul(
                        public_instance.group,
                        G_value,
                        nullptr,
                        G[i],
                        gamma_inverse,
                        bn_ctx_) == 1 &&
                    EC_POINT_mul(
                        public_instance.group,
                        term,
                        nullptr,
                        G[half + i],
                        gamma,
                        bn_ctx_) == 1 &&
                    EC_POINT_add(
                        public_instance.group,
                        G_value,
                        G_value,
                        term,
                        bn_ctx_) == 1 &&
                    EC_POINT_mul(
                        public_instance.group,
                        G_prime_value,
                        nullptr,
                        G_prime[i],
                        gamma,
                        bn_ctx_) == 1 &&
                    EC_POINT_mul(
                        public_instance.group,
                        term,
                        nullptr,
                        G_prime[half + i],
                        gamma_inverse,
                        bn_ctx_) == 1 &&
                    EC_POINT_add(
                        public_instance.group,
                        G_prime_value,
                        G_prime_value,
                        term,
                        bn_ctx_) == 1;
                if (!folded_ok)
                {
                    EC_POINT_free(G_value);
                    EC_POINT_free(G_prime_value);
                    ThrowIf(true, "InnerProduct verify folded point computation failed");
                }
                next_G.emplace_back(G_value);
                next_G_prime.emplace_back(G_prime_value);
            }
        }
        catch (...)
        {
            FreePointVector(next_G);
            FreePointVector(next_G_prime);
            ok = false;
        }
        BN_clear_free(gamma_inverse);
        gamma_inverse = nullptr;
        if (!ok)
        {
            break;
        }

        FreePointVector(G);
        FreePointVector(G_prime);
        G = std::move(next_G);
        G_prime = std::move(next_G_prime);
        ++round;
    }

    ok = ok && round == proof_message.L.size();
    if (ok)
    {
        GenerateInnerProductAlpha(public_instance, proof_message, alpha);
        next_point = EC_POINT_new(public_instance.group);
        ok =
            next_point != nullptr &&
            BN_mod_sqr(alpha_square, alpha, elgamal_.Order(), bn_ctx_) == 1 &&
            EC_POINT_mul(public_instance.group, next_point, nullptr, P, alpha_square, bn_ctx_) == 1 &&
            EC_POINT_mul(
                public_instance.group,
                term,
                nullptr,
                proof_message.A,
                alpha,
                bn_ctx_) == 1 &&
            EC_POINT_add(public_instance.group, next_point, next_point, term, bn_ctx_) == 1 &&
            EC_POINT_add(public_instance.group, next_point, next_point, proof_message.B, bn_ctx_) == 1;
        if (ok)
        {
            EC_POINT_free(P);
            P = next_point;
            next_point = nullptr;
        }
    }

    if (ok)
    {
        ok =
            EC_POINT_set_to_infinity(public_instance.group, rhs) == 1 &&
            BN_mod_mul(temp, alpha, proof_message.c, elgamal_.Order(), bn_ctx_) == 1 &&
            add_scaled_point(rhs, G[0], temp) &&
            BN_mod_mul(temp, alpha, proof_message.d, elgamal_.Order(), bn_ctx_) == 1 &&
            add_scaled_point(rhs, G_prime[0], temp) &&
            BN_mod_mul(
                scalar,
                proof_message.c,
                proof_message.d,
                elgamal_.Order(),
                bn_ctx_) == 1 &&
            add_scaled_point(rhs, H, scalar) &&
            add_scaled_point(rhs, h, proof_message.r_h) &&
            EC_POINT_cmp(public_instance.group, P, rhs, bn_ctx_) == 0;
    }

    FreePointVector(G);
    FreePointVector(G_prime);
    BN_clear_free(beta);
    BN_clear_free(e);
    BN_clear_free(gamma);
    BN_clear_free(gamma_inverse);
    BN_clear_free(gamma_square);
    BN_clear_free(inverse_square);
    BN_clear_free(alpha);
    BN_clear_free(alpha_square);
    BN_clear_free(scalar);
    BN_clear_free(temp);
    EC_POINT_free(H);
    EC_POINT_free(h);
    EC_POINT_free(P);
    EC_POINT_free(rhs);
    EC_POINT_free(term);
    EC_POINT_free(next_point);
    return ok;
}

bool SamePermutationArgument::VerifySamePermutationProof(
    const PublicInstance& public_instance,
    const ProofMessage& proof_message) const
{
    if (!IsValidPublicInstance(public_instance) ||
        !HasMatchingGrandProductGenerators(public_instance) ||
        proof_message.group != public_instance.group ||
        proof_message.grand_product.group != public_instance.group ||
        proof_message.grand_product.B == nullptr ||
        EC_POINT_is_on_curve(
            public_instance.group,
            proof_message.grand_product.B,
            bn_ctx_) != 1)
    {
        return false;
    }

    BIGNUM* alpha = BN_new();
    BIGNUM* beta = BN_new();
    BIGNUM* scalar_term = BN_new();
    BIGNUM* factor = BN_new();
    BIGNUM* p = BN_new();
    EC_POINT* expected_B = EC_POINT_new(public_instance.group);
    EC_POINT* term = EC_POINT_new(public_instance.group);
    if (alpha == nullptr ||
        beta == nullptr ||
        scalar_term == nullptr ||
        factor == nullptr ||
        p == nullptr ||
        expected_B == nullptr ||
        term == nullptr)
    {
        BN_clear_free(alpha);
        BN_clear_free(beta);
        BN_clear_free(scalar_term);
        BN_clear_free(factor);
        BN_clear_free(p);
        EC_POINT_free(expected_B);
        EC_POINT_free(term);
        return false;
    }

    GenerateSamePermutationChallenges(public_instance, alpha, beta);

    bool ok =
        BN_one(p) == 1 &&
        EC_POINT_copy(expected_B, public_instance.A.value) == 1 &&
        EC_POINT_mul(
            public_instance.group,
            term,
            nullptr,
            public_instance.M.value,
            alpha,
            bn_ctx_) == 1 &&
        EC_POINT_add(public_instance.group, expected_B, expected_B, term, bn_ctx_) == 1;

    for (std::size_t i = 0; ok && i < public_instance.g.size(); ++i)
    {
        ok =
            BN_copy(factor, public_instance.a[i]) != nullptr &&
            BN_mod_mul(
                scalar_term,
                public_instance.n[i],
                alpha,
                elgamal_.Order(),
                bn_ctx_) == 1 &&
            BN_mod_add(factor, factor, scalar_term, elgamal_.Order(), bn_ctx_) == 1 &&
            BN_mod_add(factor, factor, beta, elgamal_.Order(), bn_ctx_) == 1 &&
            BN_mod_mul(p, p, factor, elgamal_.Order(), bn_ctx_) == 1 &&
            EC_POINT_mul(
                public_instance.group,
                term,
                nullptr,
                public_instance.g[i],
                beta,
                bn_ctx_) == 1 &&
            EC_POINT_add(public_instance.group, expected_B, expected_B, term, bn_ctx_) == 1;
    }

    ok = ok &&
        EC_POINT_cmp(
            public_instance.group,
            expected_B,
            proof_message.grand_product.B,
            bn_ctx_) == 0;

    if (ok && public_instance.grand_product.p != nullptr)
    {
        ok = BN_cmp(p, public_instance.grand_product.p) == 0;
    }

    if (ok)
    {
        ok = VerifyGrandProductProof(
            public_instance.grand_product,
            public_instance.inner_product,
            proof_message.grand_product,
            proof_message.inner_product);
    }

    BN_clear_free(alpha);
    BN_clear_free(beta);
    BN_clear_free(scalar_term);
    BN_clear_free(factor);
    BN_clear_free(p);
    EC_POINT_free(expected_B);
    EC_POINT_free(term);
    return ok;
}

bool SamePermutationArgument::VerifySamePermutationProof(const Proof& proof) const
{
    return VerifySamePermutationProof(proof.public_instance, proof.message);
}

void SamePermutationArgument::GenerateGrandProductAlpha(
    const GrandProductPublicInstance& public_instance,
    BIGNUM* alpha) const
{
    ThrowIf(alpha == nullptr, "GrandProduct alpha output is invalid");

    std::string transcript("GrandProduct.alpha");
    AppendPoint(transcript, public_instance.B.value);
    AppendScalar(transcript, public_instance.p);

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), alpha);
    BN_nnmod(alpha, alpha, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(alpha))
    {
        BN_one(alpha);
    }
}

void SamePermutationArgument::GenerateGrandProductBeta(
    const GrandProductProofMessage& proof_message,
    BIGNUM* beta) const
{
    ThrowIf(beta == nullptr, "GrandProduct beta output is invalid");

    std::string transcript("GrandProduct.beta");
    AppendPoint(transcript, proof_message.C);
    AppendScalar(transcript, proof_message.r_p);

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), beta);
    BN_nnmod(beta, beta, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(beta))
    {
        BN_one(beta);
    }
}

void SamePermutationArgument::GenerateSamePermutationChallenges(
    const PublicInstance& public_instance,
    BIGNUM* alpha,
    BIGNUM* beta) const
{
    ThrowIf(alpha == nullptr || beta == nullptr, "SamePerm challenge output is invalid");

    std::string transcript("SamePerm");
    AppendPoint(transcript, public_instance.A.value);
    AppendPoint(transcript, public_instance.M.value);
    for (const BIGNUM* value : public_instance.a)
    {
        AppendScalar(transcript, value);
    }

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), alpha);
    BN_nnmod(alpha, alpha, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(alpha))
    {
        BN_one(alpha);
    }

    transcript.append("beta", 4);
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), beta);
    BN_nnmod(beta, beta, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(beta))
    {
        BN_one(beta);
    }
}

void SamePermutationArgument::GenerateInnerProductChallenges(
    const InnerProductPublicInstance& public_instance,
    BIGNUM* beta,
    BIGNUM* e) const
{
    ThrowIf(beta == nullptr || e == nullptr, "InnerProduct challenge output is invalid");

    std::string transcript("InnerProduct.beta");
    AppendPoint(transcript, public_instance.C.value);
    AppendPoint(transcript, public_instance.D.value);
    AppendScalar(transcript, public_instance.z);

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), beta);
    BN_nnmod(beta, beta, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(beta))
    {
        BN_one(beta);
    }

    transcript.append("e", 1);
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), e);
    BN_nnmod(e, e, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(e))
    {
        BN_one(e);
    }
}

void SamePermutationArgument::GenerateInnerProductRoundChallenge(
    const EC_POINT* L,
    const EC_POINT* R,
    BIGNUM* gamma) const
{
    ThrowIf(gamma == nullptr, "InnerProduct round challenge output is invalid");

    std::string transcript("InnerProduct.gamma");
    AppendPoint(transcript, L);
    AppendPoint(transcript, R);

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), gamma);
    BN_nnmod(gamma, gamma, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(gamma))
    {
        BN_one(gamma);
    }
}

void SamePermutationArgument::GenerateInnerProductAlpha(
    const InnerProductPublicInstance& public_instance,
    const InnerProductProofMessage& proof_message,
    BIGNUM* alpha) const
{
    ThrowIf(alpha == nullptr, "InnerProduct alpha output is invalid");

    std::string transcript("InnerProduct.alpha");
    AppendPoint(transcript, public_instance.C.value);
    AppendPoint(transcript, public_instance.D.value);
    AppendScalar(transcript, public_instance.z);
    AppendPoint(transcript, proof_message.A);
    AppendPoint(transcript, proof_message.B);

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), alpha);
    BN_nnmod(alpha, alpha, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(alpha))
    {
        BN_one(alpha);
    }
}

void SamePermutationArgument::AppendPoint(
    std::string& transcript,
    const EC_POINT* point) const
{
    ThrowIf(point == nullptr, "SamePerm transcript point is not initialized");
    const std::size_t point_size = EC_POINT_point2oct(
        elgamal_.Group(),
        point,
        POINT_CONVERSION_COMPRESSED,
        nullptr,
        0,
        bn_ctx_);
    ThrowIf(point_size == 0, "SamePerm transcript point size failed");

    std::vector<unsigned char> encoded(point_size);
    ThrowIf(
        EC_POINT_point2oct(
            elgamal_.Group(),
            point,
            POINT_CONVERSION_COMPRESSED,
            encoded.data(),
            encoded.size(),
            bn_ctx_) != point_size,
        "SamePerm transcript point encoding failed");
    transcript.append(reinterpret_cast<const char*>(&point_size), sizeof(point_size));
    transcript.append(reinterpret_cast<const char*>(encoded.data()), encoded.size());
}

void SamePermutationArgument::AppendScalar(
    std::string& transcript,
    const BIGNUM* scalar) const
{
    ThrowIf(scalar == nullptr, "SamePerm transcript scalar is not initialized");
    const std::size_t scalar_size = BN_num_bytes(scalar);
    transcript.append(reinterpret_cast<const char*>(&scalar_size), sizeof(scalar_size));
    if (scalar_size == 0)
    {
        return;
    }

    std::vector<unsigned char> encoded(scalar_size);
    ThrowIf(
        BN_bn2bin(scalar, encoded.data()) != static_cast<int>(scalar_size),
        "SamePerm transcript scalar encoding failed");
    transcript.append(reinterpret_cast<const char*>(encoded.data()), encoded.size());
}

bool SamePermutationArgument::IsValidPublicInstance(
    const PublicInstance& public_instance) const
{
    if (public_instance.group != elgamal_.Group() ||
        public_instance.g.empty() ||
        public_instance.g.size() != public_instance.a.size() ||
        public_instance.n.size() != public_instance.a.size() ||
        public_instance.h == nullptr ||
        public_instance.A.group != public_instance.group ||
        public_instance.M.group != public_instance.group ||
        public_instance.A.value == nullptr ||
        public_instance.M.value == nullptr)
    {
        return false;
    }

    for (std::size_t i = 0; i < public_instance.g.size(); ++i)
    {
        if (public_instance.g[i] == nullptr ||
            public_instance.a[i] == nullptr ||
            public_instance.n[i] == nullptr ||
            !BN_is_word(public_instance.n[i], static_cast<BN_ULONG>(i + 1)) ||
            EC_POINT_is_on_curve(public_instance.group, public_instance.g[i], bn_ctx_) != 1)
        {
            return false;
        }
    }

    return EC_POINT_is_on_curve(public_instance.group, public_instance.h, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(public_instance.group, public_instance.A.value, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(public_instance.group, public_instance.M.value, bn_ctx_) == 1;
}

bool SamePermutationArgument::IsValidGrandProductPublicInstance(
    const GrandProductPublicInstance& public_instance) const
{
    if (public_instance.group != elgamal_.Group() ||
        public_instance.g.empty() ||
        public_instance.h == nullptr ||
        public_instance.B.group != public_instance.group ||
        public_instance.B.value == nullptr ||
        public_instance.p == nullptr)
    {
        return false;
    }

    for (const EC_POINT* point : public_instance.g)
    {
        if (point == nullptr ||
            EC_POINT_is_on_curve(public_instance.group, point, bn_ctx_) != 1)
        {
            return false;
        }
    }

    return EC_POINT_is_on_curve(public_instance.group, public_instance.h, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(public_instance.group, public_instance.B.value, bn_ctx_) == 1;
}

bool SamePermutationArgument::HasMatchingGrandProductGenerators(
    const PublicInstance& public_instance) const
{
    const GrandProductPublicInstance& grand_product = public_instance.grand_product;
    if (public_instance.group != grand_product.group ||
        public_instance.g.size() != grand_product.g.size() ||
        public_instance.h == nullptr ||
        grand_product.h == nullptr)
    {
        return false;
    }

    for (std::size_t i = 0; i < public_instance.g.size(); ++i)
    {
        if (public_instance.g[i] == nullptr ||
            grand_product.g[i] == nullptr ||
            EC_POINT_cmp(
                public_instance.group,
                public_instance.g[i],
                grand_product.g[i],
                bn_ctx_) != 0)
        {
            return false;
        }
    }

    return EC_POINT_cmp(
        public_instance.group,
        public_instance.h,
        grand_product.h,
        bn_ctx_) == 0;
}

bool SamePermutationArgument::IsValidPermutation(
    const std::vector<std::size_t>& permutation,
    std::size_t size) const
{
    if (permutation.size() != size)
    {
        return false;
    }
    std::vector<bool> seen(size, false);
    for (std::size_t value : permutation)
    {
        if (value >= size || seen[value])
        {
            return false;
        }
        seen[value] = true;
    }
    return true;
}

bool SamePermutationArgument::VectorCommit(
    const std::vector<EC_POINT*>& g,
    const EC_POINT* h,
    const std::vector<BIGNUM*>& values,
    const BIGNUM* randomness,
    EC_POINT* result) const
{
    if (g.size() != values.size() || h == nullptr || randomness == nullptr || result == nullptr)
    {
        return false;
    }

    EC_POINT* term = EC_POINT_new(elgamal_.Group());
    if (term == nullptr ||
        EC_POINT_set_to_infinity(elgamal_.Group(), result) != 1)
    {
        EC_POINT_free(term);
        return false;
    }

    bool ok = true;
    for (std::size_t i = 0; ok && i < g.size(); ++i)
    {
        ok =
            g[i] != nullptr &&
            values[i] != nullptr &&
            EC_POINT_mul(elgamal_.Group(), term, nullptr, g[i], values[i], bn_ctx_) == 1 &&
            EC_POINT_add(elgamal_.Group(), result, result, term, bn_ctx_) == 1;
    }
    ok = ok &&
        EC_POINT_mul(elgamal_.Group(), term, nullptr, h, randomness, bn_ctx_) == 1 &&
        EC_POINT_add(elgamal_.Group(), result, result, term, bn_ctx_) == 1;

    EC_POINT_free(term);
    return ok;
}
