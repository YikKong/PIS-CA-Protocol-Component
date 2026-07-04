#include "SameMultiScalarArgument.h"

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
    std::vector<EC_POINT*> duplicates;
    duplicates.reserve(points.size());
    try
    {
        for (const EC_POINT* point : points)
        {
            EC_POINT* duplicate = DuplicatePoint(group, point);
            ThrowIf(point != nullptr && duplicate == nullptr, "SameMultiScalar point copy failed");
            duplicates.emplace_back(duplicate);
        }
    }
    catch (...)
    {
        for (EC_POINT* duplicate : duplicates)
        {
            EC_POINT_free(duplicate);
        }
        throw;
    }
    return duplicates;
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
            ThrowIf(value != nullptr && duplicate == nullptr, "SameMultiScalar scalar copy failed");
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
}

SameMultiScalarArgument::PublicInstance::PublicInstance(const PublicInstance& other)
    : group(other.group),
      ciphertexts(other.ciphertexts),
      g(DuplicatePointVector(other.group, other.g)),
      h(DuplicatePointVector(other.group, other.h)),
      G(DuplicatePointVector(other.group, other.G)),
      U(DuplicatePointVector(other.group, other.U)),
      E(DuplicatePointVector(other.group, other.E)),
      GU(DuplicatePoint(other.group, other.GU)),
      GE(DuplicatePoint(other.group, other.GE)),
      H(DuplicatePoint(other.group, other.H)),
      h1(DuplicatePoint(other.group, other.h1)),
      h2(DuplicatePoint(other.group, other.h2)),
      h3(DuplicatePoint(other.group, other.h3)),
      A_m(DuplicatePoint(other.group, other.A_m)),
      cm_um(DuplicatePoint(other.group, other.cm_um)),
      cm_em(DuplicatePoint(other.group, other.cm_em))
{
}

SameMultiScalarArgument::PublicInstance&
SameMultiScalarArgument::PublicInstance::operator=(const PublicInstance& other)
{
    if (this == &other)
    {
        return *this;
    }

    PublicInstance copy(other);
    *this = std::move(copy);
    return *this;
}

SameMultiScalarArgument::PublicInstance::PublicInstance(PublicInstance&& other) noexcept
    : group(other.group),
      ciphertexts(std::move(other.ciphertexts)),
      g(std::move(other.g)),
      h(std::move(other.h)),
      G(std::move(other.G)),
      U(std::move(other.U)),
      E(std::move(other.E)),
      GU(other.GU),
      GE(other.GE),
      H(other.H),
      h1(other.h1),
      h2(other.h2),
      h3(other.h3),
      A_m(other.A_m),
      cm_um(other.cm_um),
      cm_em(other.cm_em)
{
    other.group = nullptr;
    other.GU = nullptr;
    other.GE = nullptr;
    other.H = nullptr;
    other.h1 = nullptr;
    other.h2 = nullptr;
    other.h3 = nullptr;
    other.A_m = nullptr;
    other.cm_um = nullptr;
    other.cm_em = nullptr;
}

SameMultiScalarArgument::PublicInstance&
SameMultiScalarArgument::PublicInstance::operator=(PublicInstance&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreePointVector(g);
    FreePointVector(h);
    FreePointVector(G);
    FreePointVector(U);
    FreePointVector(E);
    EC_POINT_free(GU);
    EC_POINT_free(GE);
    EC_POINT_free(H);
    EC_POINT_free(h1);
    EC_POINT_free(h2);
    EC_POINT_free(h3);
    EC_POINT_free(A_m);
    EC_POINT_free(cm_um);
    EC_POINT_free(cm_em);
    group = other.group;
    ciphertexts = std::move(other.ciphertexts);
    g = std::move(other.g);
    h = std::move(other.h);
    G = std::move(other.G);
    U = std::move(other.U);
    E = std::move(other.E);
    GU = other.GU;
    GE = other.GE;
    H = other.H;
    h1 = other.h1;
    h2 = other.h2;
    h3 = other.h3;
    A_m = other.A_m;
    cm_um = other.cm_um;
    cm_em = other.cm_em;
    other.group = nullptr;
    other.GU = nullptr;
    other.GE = nullptr;
    other.H = nullptr;
    other.h1 = nullptr;
    other.h2 = nullptr;
    other.h3 = nullptr;
    other.A_m = nullptr;
    other.cm_um = nullptr;
    other.cm_em = nullptr;
    return *this;
}

SameMultiScalarArgument::PublicInstance::~PublicInstance()
{
    FreePointVector(g);
    FreePointVector(h);
    FreePointVector(G);
    FreePointVector(U);
    FreePointVector(E);
    EC_POINT_free(GU);
    EC_POINT_free(GE);
    EC_POINT_free(H);
    EC_POINT_free(h1);
    EC_POINT_free(h2);
    EC_POINT_free(h3);
    EC_POINT_free(A_m);
    EC_POINT_free(cm_um);
    EC_POINT_free(cm_em);
}

SameMultiScalarArgument::Witness::Witness(const Witness& other)
    : x(DuplicateBNVector(other.x)),
      sigma_a(DuplicateBNVector(other.sigma_a)),
      r_A(DuplicateBNVector(other.r_A)),
      r_u(DuplicateBN(other.r_u)),
      r_e(DuplicateBN(other.r_e)),
      r_L_randomness(DuplicateBNVector(other.r_L_randomness)),
      r_R_randomness(DuplicateBNVector(other.r_R_randomness)),
      x_randomness(DuplicateBN(other.x_randomness)),
      r_h_randomness(DuplicateBN(other.r_h_randomness))
{
    ThrowIf(other.r_u != nullptr && r_u == nullptr, "SameMultiScalar witness r_u copy failed");
    ThrowIf(other.r_e != nullptr && r_e == nullptr, "SameMultiScalar witness r_e copy failed");
    ThrowIf(
        other.x_randomness != nullptr && x_randomness == nullptr,
        "SameMultiScalar witness x randomness copy failed");
    ThrowIf(
        other.r_h_randomness != nullptr && r_h_randomness == nullptr,
        "SameMultiScalar witness r_h randomness copy failed");
}

SameMultiScalarArgument::Witness&
SameMultiScalarArgument::Witness::operator=(const Witness& other)
{
    if (this == &other)
    {
        return *this;
    }

    Witness copy(other);
    *this = std::move(copy);
    return *this;
}

SameMultiScalarArgument::Witness::Witness(Witness&& other) noexcept
    : x(std::move(other.x)),
      sigma_a(std::move(other.sigma_a)),
      r_A(std::move(other.r_A)),
      r_u(other.r_u),
      r_e(other.r_e),
      r_L_randomness(std::move(other.r_L_randomness)),
      r_R_randomness(std::move(other.r_R_randomness)),
      x_randomness(other.x_randomness),
      r_h_randomness(other.r_h_randomness)
{
    other.r_u = nullptr;
    other.r_e = nullptr;
    other.x_randomness = nullptr;
    other.r_h_randomness = nullptr;
}

SameMultiScalarArgument::Witness&
SameMultiScalarArgument::Witness::operator=(Witness&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    FreeBNVector(x);
    FreeBNVector(sigma_a);
    FreeBNVector(r_A);
    FreeBNVector(r_L_randomness);
    FreeBNVector(r_R_randomness);
    BN_clear_free(r_u);
    BN_clear_free(r_e);
    BN_clear_free(x_randomness);
    BN_clear_free(r_h_randomness);
    x = std::move(other.x);
    sigma_a = std::move(other.sigma_a);
    r_A = std::move(other.r_A);
    r_L_randomness = std::move(other.r_L_randomness);
    r_R_randomness = std::move(other.r_R_randomness);
    r_u = other.r_u;
    r_e = other.r_e;
    x_randomness = other.x_randomness;
    r_h_randomness = other.r_h_randomness;
    other.r_u = nullptr;
    other.r_e = nullptr;
    other.x_randomness = nullptr;
    other.r_h_randomness = nullptr;
    return *this;
}

SameMultiScalarArgument::Witness::~Witness()
{
    FreeBNVector(x);
    FreeBNVector(sigma_a);
    FreeBNVector(r_A);
    FreeBNVector(r_L_randomness);
    FreeBNVector(r_R_randomness);
    BN_clear_free(r_u);
    BN_clear_free(r_e);
    BN_clear_free(x_randomness);
    BN_clear_free(r_h_randomness);
}

SameMultiScalarArgument::ProofMessage::ProofMessage()
    : x(BN_new()), r_h(BN_new())
{
    ThrowIf(x == nullptr || r_h == nullptr, "SameMultiScalar proof scalar allocation failed");
}

SameMultiScalarArgument::ProofMessage::ProofMessage(const ProofMessage& other)
    : group(other.group),
      B_A(DuplicatePoint(other.group, other.B_A)),
      B_U(DuplicatePoint(other.group, other.B_U)),
      B_E(DuplicatePoint(other.group, other.B_E)),
      L_A(DuplicatePointVector(other.group, other.L_A)),
      R_A(DuplicatePointVector(other.group, other.R_A)),
      L_U(DuplicatePointVector(other.group, other.L_U)),
      R_U(DuplicatePointVector(other.group, other.R_U)),
      L_E(DuplicatePointVector(other.group, other.L_E)),
      R_E(DuplicatePointVector(other.group, other.R_E)),
      x(DuplicateBN(other.x)),
      r_h(DuplicateBN(other.r_h))
{
    ThrowIf(other.B_A != nullptr && B_A == nullptr, "SameMultiScalar proof B_A copy failed");
    ThrowIf(other.B_U != nullptr && B_U == nullptr, "SameMultiScalar proof B_U copy failed");
    ThrowIf(other.B_E != nullptr && B_E == nullptr, "SameMultiScalar proof B_E copy failed");
    ThrowIf(other.x != nullptr && x == nullptr, "SameMultiScalar proof x copy failed");
    ThrowIf(other.r_h != nullptr && r_h == nullptr, "SameMultiScalar proof r copy failed");
}

SameMultiScalarArgument::ProofMessage&
SameMultiScalarArgument::ProofMessage::operator=(const ProofMessage& other)
{
    if (this == &other)
    {
        return *this;
    }

    ProofMessage copy(other);
    *this = std::move(copy);
    return *this;
}

SameMultiScalarArgument::ProofMessage::ProofMessage(ProofMessage&& other) noexcept
    : group(other.group),
      B_A(other.B_A),
      B_U(other.B_U),
      B_E(other.B_E),
      L_A(std::move(other.L_A)),
      R_A(std::move(other.R_A)),
      L_U(std::move(other.L_U)),
      R_U(std::move(other.R_U)),
      L_E(std::move(other.L_E)),
      R_E(std::move(other.R_E)),
      x(other.x),
      r_h(other.r_h)
{
    other.group = nullptr;
    other.B_A = nullptr;
    other.B_U = nullptr;
    other.B_E = nullptr;
    other.x = nullptr;
    other.r_h = nullptr;
}

SameMultiScalarArgument::ProofMessage&
SameMultiScalarArgument::ProofMessage::operator=(ProofMessage&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    EC_POINT_free(B_A);
    EC_POINT_free(B_U);
    EC_POINT_free(B_E);
    FreePointVector(L_A);
    FreePointVector(R_A);
    FreePointVector(L_U);
    FreePointVector(R_U);
    FreePointVector(L_E);
    FreePointVector(R_E);
    BN_clear_free(x);
    BN_clear_free(r_h);
    group = other.group;
    B_A = other.B_A;
    B_U = other.B_U;
    B_E = other.B_E;
    L_A = std::move(other.L_A);
    R_A = std::move(other.R_A);
    L_U = std::move(other.L_U);
    R_U = std::move(other.R_U);
    L_E = std::move(other.L_E);
    R_E = std::move(other.R_E);
    x = other.x;
    r_h = other.r_h;
    other.group = nullptr;
    other.B_A = nullptr;
    other.B_U = nullptr;
    other.B_E = nullptr;
    other.x = nullptr;
    other.r_h = nullptr;
    return *this;
}

SameMultiScalarArgument::ProofMessage::~ProofMessage()
{
    EC_POINT_free(B_A);
    EC_POINT_free(B_U);
    EC_POINT_free(B_E);
    FreePointVector(L_A);
    FreePointVector(R_A);
    FreePointVector(L_U);
    FreePointVector(R_U);
    FreePointVector(L_E);
    FreePointVector(R_E);
    BN_clear_free(x);
    BN_clear_free(r_h);
}

SameMultiScalarArgument::SameMultiScalarArgument(const ElGamalEnc& elgamal)
    : elgamal_(elgamal), commitment_scheme_(elgamal), bn_ctx_(BN_CTX_new())
{
    ThrowIf(bn_ctx_ == nullptr, "SameMultiScalar BN_CTX allocation failed");
}

SameMultiScalarArgument::~SameMultiScalarArgument()
{
    BN_CTX_free(bn_ctx_);
}

void SameMultiScalarArgument::InitializePublicInstance(
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
    Witness& witness) const
{
    const EC_GROUP* group = commitment_key.group;
    std::vector<BIGNUM*> x_parts;
    x_parts.reserve(sigma_a.size() + r_A.size() + 2);
    for (BIGNUM* value : sigma_a)
    {
        x_parts.emplace_back(value);
    }
    for (BIGNUM* value : r_A)
    {
        x_parts.emplace_back(value);
    }
    x_parts.emplace_back(const_cast<BIGNUM*>(r_u));
    x_parts.emplace_back(const_cast<BIGNUM*>(r_e));

    ThrowIf(
        !commitment_scheme_.IsValidCommitmentKey(commitment_key) ||
            !elgamal_.IsValidCommitment(A) ||
            !commitment_scheme_.IsValidCommitment(cm_u) ||
            !commitment_scheme_.IsValidCommitment(cm_e) ||
            group != elgamal_.Group() ||
            A.group != group ||
            cm_u.group != group ||
            cm_e.group != group ||
            ciphertexts.empty() || ciphertexts.size() != sigma_a.size() ||
            g.size() != sigma_a.size() || h.size() != r_A.size() ||
            x_parts.empty() || !IsPowerOfTwo(x_parts.size()) ||
            r_u == nullptr || r_e == nullptr,
            "SameMultiScalar public instance input size mismatch");

    for (const Ciphertext& ciphertext : ciphertexts)
    {
        ThrowIf(
            ciphertext.group != group || !elgamal_.IsValidCiphertext(ciphertext),
            "SameMultiScalar ciphertext input is invalid");
    }
    for (const std::vector<EC_POINT*>* subvector : {&g, &h})
    {
        for (const EC_POINT* point : *subvector)
        {
            ThrowIf(
                point == nullptr || EC_POINT_is_on_curve(group, point, bn_ctx_) != 1,
                "SameMultiScalar public subvector input is invalid");
        }
    }
    std::vector<EC_POINT*> extended_G;
    std::vector<EC_POINT*> extended_U;
    std::vector<EC_POINT*> extended_E;
    extended_G.reserve(x_parts.size());
    extended_U.reserve(x_parts.size());
    extended_E.reserve(x_parts.size());
    try
    {
        for (std::size_t i = 0; i < sigma_a.size(); ++i)
        {
            extended_G.emplace_back(DuplicatePoint(group, g[i]));
            extended_U.emplace_back(DuplicatePoint(group, ciphertexts[i].u));
            extended_E.emplace_back(DuplicatePoint(group, ciphertexts[i].e));
        }
        for (const EC_POINT* h_point : h)
        {
            EC_POINT* zero_u = EC_POINT_new(group);
            EC_POINT* zero_e = EC_POINT_new(group);
            ThrowIf(
                zero_u == nullptr || zero_e == nullptr ||
                    EC_POINT_set_to_infinity(group, zero_u) != 1 ||
                    EC_POINT_set_to_infinity(group, zero_e) != 1,
                "SameMultiScalar zero base allocation failed");
            extended_G.emplace_back(DuplicatePoint(group, h_point));
            extended_U.emplace_back(zero_u);
            extended_E.emplace_back(zero_e);
        }

        EC_POINT* zero_e_ru = EC_POINT_new(group);
        EC_POINT* zero_u_re = EC_POINT_new(group);
        ThrowIf(
            zero_e_ru == nullptr || zero_u_re == nullptr ||
                EC_POINT_set_to_infinity(group, zero_e_ru) != 1 ||
                EC_POINT_set_to_infinity(group, zero_u_re) != 1,
            "SameMultiScalar terminal zero base allocation failed");
        extended_G.emplace_back(DuplicatePoint(group, commitment_key.GU));
        extended_U.emplace_back(DuplicatePoint(group, commitment_key.H));
        extended_E.emplace_back(zero_e_ru);
        extended_G.emplace_back(DuplicatePoint(group, commitment_key.GE));
        extended_U.emplace_back(zero_u_re);
        extended_E.emplace_back(DuplicatePoint(group, commitment_key.H));

        for (std::size_t i = 0; i < x_parts.size(); ++i)
        {
            ThrowIf(
                extended_G[i] == nullptr ||
                    extended_U[i] == nullptr ||
                    extended_E[i] == nullptr ||
                    x_parts[i] == nullptr,
                "SameMultiScalar extended base allocation failed");
        }
    }
    catch (...)
    {
        FreePointVector(extended_G);
        FreePointVector(extended_U);
        FreePointVector(extended_E);
        throw;
    }

    PublicInstance next;
    next.group = group;
    next.ciphertexts = ciphertexts;
    next.g = DuplicatePointVector(group, g);
    next.h = DuplicatePointVector(group, h);
    next.G = DuplicatePointVector(group, extended_G);
    next.U = DuplicatePointVector(group, extended_U);
    next.E = DuplicatePointVector(group, extended_E);
    next.GU = DuplicatePoint(group, commitment_key.GU);
    next.GE = DuplicatePoint(group, commitment_key.GE);
    next.H = DuplicatePoint(group, commitment_key.H);
    next.h1 = EC_POINT_new(group);
    next.h2 = EC_POINT_new(group);
    next.h3 = EC_POINT_new(group);
    ThrowIf(
        next.h1 == nullptr || next.h2 == nullptr || next.h3 == nullptr,
        "SameMultiScalar h base allocation failed");
    elgamal_.GenerateRandomGroupElement(next.h1);
    elgamal_.GenerateRandomGroupElement(next.h2);
    elgamal_.GenerateRandomGroupElement(next.h3);
    next.A_m = EC_POINT_new(group);
    next.cm_um = EC_POINT_new(group);
    next.cm_em = EC_POINT_new(group);
    Witness next_witness;
    next_witness.x = DuplicateBNVector(x_parts);
    next_witness.sigma_a = DuplicateBNVector(sigma_a);
    next_witness.r_A = DuplicateBNVector(r_A);
    next_witness.r_u = DuplicateBN(r_u);
    next_witness.r_e = DuplicateBN(r_e);
    ThrowIf(
        next.h1 == nullptr || next.h2 == nullptr || next.h3 == nullptr ||
            next.GU == nullptr || next.GE == nullptr || next.H == nullptr ||
            next.A_m == nullptr || next.cm_um == nullptr || next.cm_em == nullptr ||
            next_witness.r_u == nullptr || next_witness.r_e == nullptr ||
            EC_POINT_copy(next.A_m, A.value) != 1 ||
            EC_POINT_add(group, next.A_m, next.A_m, cm_u.first, bn_ctx_) != 1 ||
            EC_POINT_add(group, next.A_m, next.A_m, cm_e.first, bn_ctx_) != 1 ||
            EC_POINT_copy(next.cm_um, cm_u.second) != 1 ||
            EC_POINT_copy(next.cm_em, cm_e.second) != 1,
        "SameMultiScalar public instance allocation failed");

    FreePointVector(extended_G);
    FreePointVector(extended_U);
    FreePointVector(extended_E);
    public_instance = std::move(next);
    witness = std::move(next_witness);
}

void SameMultiScalarArgument::CreateProof(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance,
    const Witness& witness,
    Proof& proof) const
{
    ThrowIf(!IsValidPublicInstance(commitment_key, public_instance) ||
            witness.x.size() != public_instance.G.size(),
        "SameMultiScalar proof input is invalid");

    const EC_GROUP* group = commitment_key.group;
    proof.public_instance = public_instance;
    proof.witness = witness;
    FreeBNVector(proof.witness.r_L_randomness);
    FreeBNVector(proof.witness.r_R_randomness);
    BN_clear_free(proof.witness.x_randomness);
    BN_clear_free(proof.witness.r_h_randomness);
    proof.witness.x_randomness = nullptr;
    proof.witness.r_h_randomness = nullptr;
    proof.message = ProofMessage();
    proof.message.group = group;

    std::vector<EC_POINT*> G = DuplicatePointVector(group, public_instance.G);
    std::vector<EC_POINT*> U = DuplicatePointVector(group, public_instance.U);
    std::vector<EC_POINT*> E = DuplicatePointVector(group, public_instance.E);
    std::vector<BIGNUM*> x = DuplicateBNVector(witness.x);
    BIGNUM* beta = BN_new();
    BIGNUM* gamma = BN_new();
    BIGNUM* gamma_inverse = BN_new();
    BIGNUM* r_left = BN_new();
    BIGNUM* r_right = BN_new();
    BIGNUM* r_h = BN_new();
    BIGNUM* temp_scalar = BN_new();
    EC_POINT* h1 = EC_POINT_new(group);
    EC_POINT* h2 = EC_POINT_new(group);
    EC_POINT* h3 = EC_POINT_new(group);
    EC_POINT* term = EC_POINT_new(group);
    ThrowIf(
        beta == nullptr || gamma == nullptr || gamma_inverse == nullptr ||
            r_left == nullptr || r_right == nullptr || r_h == nullptr ||
            temp_scalar == nullptr || h1 == nullptr || h2 == nullptr ||
            h3 == nullptr || term == nullptr,
        "SameMultiScalar proof temporary allocation failed");

    GenerateChallenge(
        group,
        "SameMultiScalar.beta",
        {public_instance.A_m, public_instance.cm_um, public_instance.cm_em},
        beta);
    ThrowIf(
        EC_POINT_mul(group, h1, nullptr, public_instance.h1, beta, bn_ctx_) != 1 ||
            EC_POINT_mul(group, h2, nullptr, public_instance.h2, beta, bn_ctx_) != 1 ||
            EC_POINT_mul(group, h3, nullptr, public_instance.h3, beta, bn_ctx_) != 1 ||
            BN_set_word(r_h, 0) != 1,
        "SameMultiScalar beta setup failed");

    while (x.size() > 1)
    {
        const std::size_t half = x.size() / 2;
        EC_POINT* L_A = EC_POINT_new(group);
        EC_POINT* R_A = EC_POINT_new(group);
        EC_POINT* L_U = EC_POINT_new(group);
        EC_POINT* R_U = EC_POINT_new(group);
        EC_POINT* L_E = EC_POINT_new(group);
        EC_POINT* R_E = EC_POINT_new(group);
        ThrowIf(
            L_A == nullptr || R_A == nullptr || L_U == nullptr ||
                R_U == nullptr || L_E == nullptr || R_E == nullptr ||
                EC_POINT_set_to_infinity(group, L_A) != 1 ||
                EC_POINT_set_to_infinity(group, R_A) != 1 ||
                EC_POINT_set_to_infinity(group, L_U) != 1 ||
                EC_POINT_set_to_infinity(group, R_U) != 1 ||
                EC_POINT_set_to_infinity(group, L_E) != 1 ||
                EC_POINT_set_to_infinity(group, R_E) != 1,
            "SameMultiScalar round point allocation failed");

        elgamal_.GenerateRandomScalar(r_left);
        elgamal_.GenerateRandomScalar(r_right);
        proof.witness.r_L_randomness.emplace_back(DuplicateBN(r_left));
        proof.witness.r_R_randomness.emplace_back(DuplicateBN(r_right));
        ThrowIf(
            proof.witness.r_L_randomness.back() == nullptr ||
                proof.witness.r_R_randomness.back() == nullptr,
            "SameMultiScalar round randomness copy failed");
        for (std::size_t i = 0; i < half; ++i)
        {
            ThrowIf(
                EC_POINT_mul(group, term, nullptr, G[half + i], x[i], bn_ctx_) != 1 ||
                    EC_POINT_add(group, L_A, L_A, term, bn_ctx_) != 1 ||
                    EC_POINT_mul(group, term, nullptr, G[i], x[half + i], bn_ctx_) != 1 ||
                    EC_POINT_add(group, R_A, R_A, term, bn_ctx_) != 1 ||
                    EC_POINT_mul(group, term, nullptr, U[half + i], x[i], bn_ctx_) != 1 ||
                    EC_POINT_add(group, L_U, L_U, term, bn_ctx_) != 1 ||
                    EC_POINT_mul(group, term, nullptr, U[i], x[half + i], bn_ctx_) != 1 ||
                    EC_POINT_add(group, R_U, R_U, term, bn_ctx_) != 1 ||
                    EC_POINT_mul(group, term, nullptr, E[half + i], x[i], bn_ctx_) != 1 ||
                    EC_POINT_add(group, L_E, L_E, term, bn_ctx_) != 1 ||
                    EC_POINT_mul(group, term, nullptr, E[i], x[half + i], bn_ctx_) != 1 ||
                    EC_POINT_add(group, R_E, R_E, term, bn_ctx_) != 1,
                "SameMultiScalar round cross-term computation failed");
        }

        ThrowIf(
            EC_POINT_mul(group, term, nullptr, h1, r_left, bn_ctx_) != 1 ||
                EC_POINT_add(group, L_A, L_A, term, bn_ctx_) != 1 ||
                EC_POINT_mul(group, term, nullptr, h1, r_right, bn_ctx_) != 1 ||
                EC_POINT_add(group, R_A, R_A, term, bn_ctx_) != 1 ||
                EC_POINT_mul(group, term, nullptr, h2, r_left, bn_ctx_) != 1 ||
                EC_POINT_add(group, L_U, L_U, term, bn_ctx_) != 1 ||
                EC_POINT_mul(group, term, nullptr, h2, r_right, bn_ctx_) != 1 ||
                EC_POINT_add(group, R_U, R_U, term, bn_ctx_) != 1 ||
                EC_POINT_mul(group, term, nullptr, h3, r_left, bn_ctx_) != 1 ||
                EC_POINT_add(group, L_E, L_E, term, bn_ctx_) != 1 ||
                EC_POINT_mul(group, term, nullptr, h3, r_right, bn_ctx_) != 1 ||
                EC_POINT_add(group, R_E, R_E, term, bn_ctx_) != 1,
            "SameMultiScalar round randomizer computation failed");

        GenerateChallenge(
            group,
            "SameMultiScalar.gamma",
            {L_A, R_A, L_U, R_U, L_E, R_E},
            gamma);
        ThrowIf(BN_mod_inverse(gamma_inverse, gamma, elgamal_.Order(), bn_ctx_) == nullptr,
            "SameMultiScalar challenge inverse failed");

        std::vector<EC_POINT*> next_G;
        std::vector<EC_POINT*> next_U;
        std::vector<EC_POINT*> next_E;
        std::vector<BIGNUM*> next_x;
        next_G.reserve(half);
        next_U.reserve(half);
        next_E.reserve(half);
        next_x.reserve(half);
        for (std::size_t i = 0; i < half; ++i)
        {
            EC_POINT* g = EC_POINT_new(group);
            EC_POINT* u = EC_POINT_new(group);
            EC_POINT* e = EC_POINT_new(group);
            BIGNUM* folded_x = BN_new();
            ThrowIf(g == nullptr || u == nullptr || e == nullptr || folded_x == nullptr,
                "SameMultiScalar folded value allocation failed");
            ThrowIf(
                EC_POINT_mul(group, term, nullptr, G[half + i], gamma, bn_ctx_) != 1 ||
                    EC_POINT_add(group, g, G[i], term, bn_ctx_) != 1 ||
                    EC_POINT_mul(group, term, nullptr, U[half + i], gamma, bn_ctx_) != 1 ||
                    EC_POINT_add(group, u, U[i], term, bn_ctx_) != 1 ||
                    EC_POINT_mul(group, term, nullptr, E[half + i], gamma, bn_ctx_) != 1 ||
                    EC_POINT_add(group, e, E[i], term, bn_ctx_) != 1 ||
                    BN_mod_mul(folded_x, gamma_inverse, x[half + i], elgamal_.Order(), bn_ctx_) != 1 ||
                    BN_mod_add(folded_x, x[i], folded_x, elgamal_.Order(), bn_ctx_) != 1,
                "SameMultiScalar folding failed");
            next_G.emplace_back(g);
            next_U.emplace_back(u);
            next_E.emplace_back(e);
            next_x.emplace_back(folded_x);
        }

        BN_mod_mul(temp_scalar, r_left, gamma, elgamal_.Order(), bn_ctx_);
        BN_mod_add(r_h, r_h, temp_scalar, elgamal_.Order(), bn_ctx_);
        BN_mod_mul(temp_scalar, r_right, gamma_inverse, elgamal_.Order(), bn_ctx_);
        BN_mod_add(r_h, r_h, temp_scalar, elgamal_.Order(), bn_ctx_);

        FreePointVector(G);
        FreePointVector(U);
        FreePointVector(E);
        FreeBNVector(x);
        G = std::move(next_G);
        U = std::move(next_U);
        E = std::move(next_E);
        x = std::move(next_x);
        proof.message.L_A.emplace_back(L_A);
        proof.message.R_A.emplace_back(R_A);
        proof.message.L_U.emplace_back(L_U);
        proof.message.R_U.emplace_back(R_U);
        proof.message.L_E.emplace_back(L_E);
        proof.message.R_E.emplace_back(R_E);
    }

    BIGNUM* random_x = BN_new();
    BIGNUM* random_r = BN_new();
    BIGNUM* alpha = BN_new();
    ThrowIf(random_x == nullptr || random_r == nullptr || alpha == nullptr,
        "SameMultiScalar final proof allocation failed");
    proof.message.B_A = EC_POINT_new(group);
    proof.message.B_U = EC_POINT_new(group);
    proof.message.B_E = EC_POINT_new(group);
    elgamal_.GenerateRandomScalar(random_x);
    elgamal_.GenerateRandomScalar(random_r);
    proof.witness.x_randomness = DuplicateBN(random_x);
    proof.witness.r_h_randomness = DuplicateBN(random_r);
    ThrowIf(
        proof.witness.x_randomness == nullptr ||
            proof.witness.r_h_randomness == nullptr ||
            proof.message.B_A == nullptr || proof.message.B_U == nullptr ||
            proof.message.B_E == nullptr ||
            EC_POINT_mul(group, proof.message.B_A, nullptr, G[0], random_x, bn_ctx_) != 1 ||
            EC_POINT_mul(group, term, nullptr, h1, random_r, bn_ctx_) != 1 ||
            EC_POINT_add(group, proof.message.B_A, proof.message.B_A, term, bn_ctx_) != 1 ||
            EC_POINT_mul(group, proof.message.B_U, nullptr, U[0], random_x, bn_ctx_) != 1 ||
            EC_POINT_mul(group, term, nullptr, h2, random_r, bn_ctx_) != 1 ||
            EC_POINT_add(group, proof.message.B_U, proof.message.B_U, term, bn_ctx_) != 1 ||
            EC_POINT_mul(group, proof.message.B_E, nullptr, E[0], random_x, bn_ctx_) != 1 ||
            EC_POINT_mul(group, term, nullptr, h3, random_r, bn_ctx_) != 1 ||
            EC_POINT_add(group, proof.message.B_E, proof.message.B_E, term, bn_ctx_) != 1,
        "SameMultiScalar final proof commitment failed");

    GenerateChallenge(
        group,
        "SameMultiScalar.alpha",
        {proof.message.B_A, proof.message.B_U, proof.message.B_E},
        alpha);
    BN_mod_mul(temp_scalar, alpha, x[0], elgamal_.Order(), bn_ctx_);
    BN_mod_add(proof.message.x, random_x, temp_scalar, elgamal_.Order(), bn_ctx_);
    BN_mod_mul(temp_scalar, alpha, r_h, elgamal_.Order(), bn_ctx_);
    BN_mod_add(proof.message.r_h, random_r, temp_scalar, elgamal_.Order(), bn_ctx_);

    BN_clear_free(beta);
    BN_clear_free(gamma);
    BN_clear_free(gamma_inverse);
    BN_clear_free(r_left);
    BN_clear_free(r_right);
    BN_clear_free(r_h);
    BN_clear_free(temp_scalar);
    BN_clear_free(random_x);
    BN_clear_free(random_r);
    BN_clear_free(alpha);
    EC_POINT_free(h1);
    EC_POINT_free(h2);
    EC_POINT_free(h3);
    EC_POINT_free(term);
    FreePointVector(G);
    FreePointVector(U);
    FreePointVector(E);
    FreeBNVector(x);
}

bool SameMultiScalarArgument::VerifyProof(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance,
    const ProofMessage& proof_message) const
{
    if (!IsValidPublicInstance(commitment_key, public_instance) ||
        proof_message.B_A == nullptr || proof_message.B_U == nullptr ||
        proof_message.B_E == nullptr || proof_message.x == nullptr ||
        proof_message.r_h == nullptr)
    {
        return false;
    }

    const std::size_t rounds = proof_message.L_A.size();
    if (rounds != proof_message.R_A.size() ||
        rounds != proof_message.L_U.size() ||
        rounds != proof_message.R_U.size() ||
        rounds != proof_message.L_E.size() ||
        rounds != proof_message.R_E.size())
    {
        return false;
    }

    const EC_GROUP* group = commitment_key.group;
    std::vector<EC_POINT*> G = DuplicatePointVector(group, public_instance.G);
    std::vector<EC_POINT*> U = DuplicatePointVector(group, public_instance.U);
    std::vector<EC_POINT*> E = DuplicatePointVector(group, public_instance.E);
    EC_POINT* A = DuplicatePoint(group, public_instance.A_m);
    EC_POINT* C_U = DuplicatePoint(group, public_instance.cm_um);
    EC_POINT* C_E = DuplicatePoint(group, public_instance.cm_em);
    EC_POINT* h1 = EC_POINT_new(group);
    EC_POINT* h2 = EC_POINT_new(group);
    EC_POINT* h3 = EC_POINT_new(group);
    EC_POINT* term = EC_POINT_new(group);
    BIGNUM* beta = BN_new();
    BIGNUM* gamma = BN_new();
    BIGNUM* gamma_inverse = BN_new();
    BIGNUM* alpha = BN_new();
    bool ok = A != nullptr && C_U != nullptr && C_E != nullptr &&
        h1 != nullptr && h2 != nullptr && h3 != nullptr && term != nullptr &&
        beta != nullptr && gamma != nullptr && gamma_inverse != nullptr &&
        alpha != nullptr;
    if (!ok)
    {
        FreePointVector(G);
        FreePointVector(U);
        FreePointVector(E);
        EC_POINT_free(A);
        EC_POINT_free(C_U);
        EC_POINT_free(C_E);
        EC_POINT_free(h1);
        EC_POINT_free(h2);
        EC_POINT_free(h3);
        EC_POINT_free(term);
        BN_clear_free(beta);
        BN_clear_free(gamma);
        BN_clear_free(gamma_inverse);
        BN_clear_free(alpha);
        return false;
    }

    GenerateChallenge(
        group,
        "SameMultiScalar.beta",
        {public_instance.A_m, public_instance.cm_um, public_instance.cm_em},
        beta);
    ok =
        EC_POINT_mul(group, h1, nullptr, public_instance.h1, beta, bn_ctx_) == 1 &&
        EC_POINT_mul(group, h2, nullptr, public_instance.h2, beta, bn_ctx_) == 1 &&
        EC_POINT_mul(group, h3, nullptr, public_instance.h3, beta, bn_ctx_) == 1;

    for (std::size_t round = 0; ok && round < rounds; ++round)
    {
        if (G.size() <= 1 || G.size() % 2 != 0 ||
            proof_message.L_A[round] == nullptr || proof_message.R_A[round] == nullptr ||
            proof_message.L_U[round] == nullptr || proof_message.R_U[round] == nullptr ||
            proof_message.L_E[round] == nullptr || proof_message.R_E[round] == nullptr)
        {
            ok = false;
            break;
        }

        GenerateChallenge(
            group,
            "SameMultiScalar.gamma",
            {proof_message.L_A[round], proof_message.R_A[round],
             proof_message.L_U[round], proof_message.R_U[round],
             proof_message.L_E[round], proof_message.R_E[round]},
            gamma);
        ok = BN_mod_inverse(gamma_inverse, gamma, elgamal_.Order(), bn_ctx_) != nullptr;
        if (!ok)
        {
            break;
        }

        ok =
            EC_POINT_mul(group, term, nullptr, proof_message.L_A[round], gamma, bn_ctx_) == 1 &&
            EC_POINT_add(group, A, term, A, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, proof_message.R_A[round], gamma_inverse, bn_ctx_) == 1 &&
            EC_POINT_add(group, A, term, A, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, proof_message.L_U[round], gamma, bn_ctx_) == 1 &&
            EC_POINT_add(group, C_U, term, C_U, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, proof_message.R_U[round], gamma_inverse, bn_ctx_) == 1 &&
            EC_POINT_add(group, C_U, term, C_U, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, proof_message.L_E[round], gamma, bn_ctx_) == 1 &&
            EC_POINT_add(group, C_E, term, C_E, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, proof_message.R_E[round], gamma_inverse, bn_ctx_) == 1 &&
            EC_POINT_add(group, C_E, term, C_E, bn_ctx_) == 1;
        if (!ok)
        {
            break;
        }

        const std::size_t half = G.size() / 2;
        std::vector<EC_POINT*> next_G;
        std::vector<EC_POINT*> next_U;
        std::vector<EC_POINT*> next_E;
        next_G.reserve(half);
        next_U.reserve(half);
        next_E.reserve(half);
        for (std::size_t i = 0; ok && i < half; ++i)
        {
            EC_POINT* g = EC_POINT_new(group);
            EC_POINT* u = EC_POINT_new(group);
            EC_POINT* e = EC_POINT_new(group);
            ok = g != nullptr && u != nullptr && e != nullptr &&
                EC_POINT_mul(group, term, nullptr, G[half + i], gamma, bn_ctx_) == 1 &&
                EC_POINT_add(group, g, G[i], term, bn_ctx_) == 1 &&
                EC_POINT_mul(group, term, nullptr, U[half + i], gamma, bn_ctx_) == 1 &&
                EC_POINT_add(group, u, U[i], term, bn_ctx_) == 1 &&
                EC_POINT_mul(group, term, nullptr, E[half + i], gamma, bn_ctx_) == 1 &&
                EC_POINT_add(group, e, E[i], term, bn_ctx_) == 1;
            if (ok)
            {
                next_G.emplace_back(g);
                next_U.emplace_back(u);
                next_E.emplace_back(e);
            }
            else
            {
                EC_POINT_free(g);
                EC_POINT_free(u);
                EC_POINT_free(e);
            }
        }
        FreePointVector(G);
        FreePointVector(U);
        FreePointVector(E);
        G = std::move(next_G);
        U = std::move(next_U);
        E = std::move(next_E);
    }

    if (ok)
    {
        ok = G.size() == 1 && U.size() == 1 && E.size() == 1;
    }

    if (ok)
    {
        GenerateChallenge(
            group,
            "SameMultiScalar.alpha",
            {proof_message.B_A, proof_message.B_U, proof_message.B_E},
            alpha);
        ok =
            EC_POINT_mul(group, term, nullptr, A, alpha, bn_ctx_) == 1 &&
            EC_POINT_add(group, A, proof_message.B_A, term, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, C_U, alpha, bn_ctx_) == 1 &&
            EC_POINT_add(group, C_U, proof_message.B_U, term, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, C_E, alpha, bn_ctx_) == 1 &&
            EC_POINT_add(group, C_E, proof_message.B_E, term, bn_ctx_) == 1;
    }

    if (ok)
    {
        EC_POINT* expected = EC_POINT_new(group);
        ok = expected != nullptr &&
            EC_POINT_mul(group, expected, nullptr, G[0], proof_message.x, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, h1, proof_message.r_h, bn_ctx_) == 1 &&
            EC_POINT_add(group, expected, expected, term, bn_ctx_) == 1 &&
            EC_POINT_cmp(group, A, expected, bn_ctx_) == 0 &&
            EC_POINT_mul(group, expected, nullptr, U[0], proof_message.x, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, h2, proof_message.r_h, bn_ctx_) == 1 &&
            EC_POINT_add(group, expected, expected, term, bn_ctx_) == 1 &&
            EC_POINT_cmp(group, C_U, expected, bn_ctx_) == 0 &&
            EC_POINT_mul(group, expected, nullptr, E[0], proof_message.x, bn_ctx_) == 1 &&
            EC_POINT_mul(group, term, nullptr, h3, proof_message.r_h, bn_ctx_) == 1 &&
            EC_POINT_add(group, expected, expected, term, bn_ctx_) == 1 &&
            EC_POINT_cmp(group, C_E, expected, bn_ctx_) == 0;
        EC_POINT_free(expected);
    }

    FreePointVector(G);
    FreePointVector(U);
    FreePointVector(E);
    EC_POINT_free(A);
    EC_POINT_free(C_U);
    EC_POINT_free(C_E);
    EC_POINT_free(h1);
    EC_POINT_free(h2);
    EC_POINT_free(h3);
    EC_POINT_free(term);
    BN_clear_free(beta);
    BN_clear_free(gamma);
    BN_clear_free(gamma_inverse);
    BN_clear_free(alpha);
    return ok;
}

bool SameMultiScalarArgument::VerifyProof(
    const CommitmentKey& commitment_key,
    const Proof& proof) const
{
    return VerifyProof(commitment_key, proof.public_instance, proof.message);
}

void SameMultiScalarArgument::GenerateChallenge(
    const EC_GROUP* group,
    const std::string& label,
    const std::vector<const EC_POINT*>& points,
    BIGNUM* challenge) const
{
    std::string transcript(label);
    for (const EC_POINT* point : points)
    {
        AppendPoint(transcript, group, point);
    }

    std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
    SHA256(
        reinterpret_cast<const unsigned char*>(transcript.data()),
        transcript.size(),
        digest.data());
    BN_bin2bn(digest.data(), digest.size(), challenge);
    BN_nnmod(challenge, challenge, elgamal_.Order(), bn_ctx_);
    if (BN_is_zero(challenge))
    {
        BN_one(challenge);
    }
}

void SameMultiScalarArgument::AppendPoint(
    std::string& transcript,
    const EC_GROUP* group,
    const EC_POINT* point) const
{
    ThrowIf(
        group == nullptr || point == nullptr,
        "SameMultiScalar transcript point is not initialized");
    const std::size_t point_size = EC_POINT_point2oct(
        group,
        point,
        POINT_CONVERSION_COMPRESSED,
        nullptr,
        0,
        bn_ctx_);
    ThrowIf(point_size == 0, "SameMultiScalar transcript point size failed");

    std::vector<unsigned char> encoded(point_size);
    ThrowIf(
        EC_POINT_point2oct(
            group,
            point,
            POINT_CONVERSION_COMPRESSED,
            encoded.data(),
            encoded.size(),
            bn_ctx_) != point_size,
        "SameMultiScalar transcript point encoding failed");
    transcript.append(reinterpret_cast<const char*>(&point_size), sizeof(point_size));
    transcript.append(reinterpret_cast<const char*>(encoded.data()), encoded.size());
}

bool SameMultiScalarArgument::IsValidPublicInstance(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance) const
{
    const EC_GROUP* group = commitment_key.group;
    if (!commitment_scheme_.IsValidCommitmentKey(commitment_key) ||
        group != elgamal_.Group() ||
        public_instance.group != group ||
        public_instance.ciphertexts.empty() ||
        public_instance.g.empty() ||
        public_instance.G.empty() ||
        public_instance.G.size() != public_instance.U.size() ||
        public_instance.G.size() != public_instance.E.size() ||
        public_instance.ciphertexts.size() != public_instance.g.size() ||
        public_instance.G.size() != public_instance.g.size() + public_instance.h.size() + 2 ||
        !IsPowerOfTwo(public_instance.G.size()) ||
        public_instance.GU == nullptr ||
        public_instance.GE == nullptr ||
        public_instance.H == nullptr ||
        public_instance.h1 == nullptr ||
        public_instance.h2 == nullptr ||
        public_instance.h3 == nullptr ||
        public_instance.A_m == nullptr ||
        public_instance.cm_um == nullptr ||
        public_instance.cm_em == nullptr)
    {
        return false;
    }

    if (EC_POINT_cmp(group, public_instance.GU, commitment_key.GU, bn_ctx_) != 0 ||
        EC_POINT_cmp(group, public_instance.GE, commitment_key.GE, bn_ctx_) != 0 ||
        EC_POINT_cmp(group, public_instance.H, commitment_key.H, bn_ctx_) != 0)
    {
        return false;
    }

    for (const Ciphertext& ciphertext : public_instance.ciphertexts)
    {
        if (ciphertext.group != group || !elgamal_.IsValidCiphertext(ciphertext))
        {
            return false;
        }
    }

    for (const std::vector<EC_POINT*>* subvector :
         {&public_instance.g, &public_instance.h})
    {
        for (const EC_POINT* point : *subvector)
        {
            if (point == nullptr || EC_POINT_is_on_curve(group, point, bn_ctx_) != 1)
            {
                return false;
            }
        }
    }

    for (std::size_t i = 0; i < public_instance.G.size(); ++i)
    {
        if (public_instance.G[i] == nullptr ||
            public_instance.U[i] == nullptr ||
            public_instance.E[i] == nullptr ||
            EC_POINT_is_on_curve(group, public_instance.G[i], bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(group, public_instance.U[i], bn_ctx_) != 1 ||
            EC_POINT_is_on_curve(group, public_instance.E[i], bn_ctx_) != 1)
        {
            return false;
        }
    }

    return EC_POINT_is_on_curve(group, public_instance.h1, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.GU, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.GE, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.H, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.h2, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.h3, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.A_m, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.cm_um, bn_ctx_) == 1 &&
        EC_POINT_is_on_curve(group, public_instance.cm_em, bn_ctx_) == 1;
}

bool SameMultiScalarArgument::IsPowerOfTwo(std::size_t value) const
{
    return value != 0 && (value & (value - 1)) == 0;
}
