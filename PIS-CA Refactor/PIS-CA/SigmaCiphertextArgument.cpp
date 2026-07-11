#include "SigmaCiphertextArgument.h"

#include <array>
#include <sstream>
#include <stdexcept>
#include <string>

namespace
{
void ThrowIf(bool failed, const char* message)
{
    if (failed)
    {
        throw std::runtime_error(message);
    }
}

std::string ToString(const NTL::ZZ& value)
{
    std::ostringstream out;
    out << value;
    return out.str();
}

EC_POINT* DuplicatePoint(const EC_GROUP* group, const EC_POINT* point)
{
    return point == nullptr ? nullptr : EC_POINT_dup(point, group);
}
}

SigmaCiphertextArgument::SigmaCiphertextArgument(const ElGamalEnc& elgamal)
    : elgamal_(elgamal),
      same_scalar_(elgamal),
      same_multi_scalar_(elgamal),
      bn_ctx_(BN_CTX_new())
{
    ThrowIf(bn_ctx_ == nullptr, "Sigma ciphertext argument BN_CTX allocation failed");
}

SigmaCiphertextArgument::~SigmaCiphertextArgument()
{
    BN_CTX_free(bn_ctx_);
}

void SigmaCiphertextArgument::CreateProof(
    const PublicKey& public_key,
    const ArgumentCommitmentKey& argument_commitment_key,
    const BetaCommitmentKey& beta_commitment_key,
    const std::vector<GroupElement>& g_values,
    const std::vector<BetaCommitment>& beta_commitments,
    const std::vector<std::shared_ptr<BIGNUM>>& beta_commitment_randomness,
    const std::vector<NTL::ZZ>& beta,
    const std::vector<Ciphertext>& sigma_ciphertexts,
    const std::vector<std::shared_ptr<BIGNUM>>& sigma_encryption_randomness,
    Proof& proof) const
{
    const std::size_t count = sigma_ciphertexts.size();
    ThrowIf(
        count == 0 ||
            g_values.size() < count ||
            beta_commitments.size() < count ||
            beta_commitment_randomness.size() < count ||
            beta.size() < count ||
            sigma_encryption_randomness.size() < count,
        "Sigma ciphertext argument input sizes are invalid");

    std::vector<std::shared_ptr<BIGNUM>> c_challenges;
    std::vector<std::shared_ptr<BIGNUM>> d_challenges;
    std::vector<Ciphertext> ct_g;
    Ciphertext aggregate_ct_g;
    std::vector<Ciphertext> weighted_sigma_ciphertexts;
    BetaCommitment aggregate_beta_commitment;
    std::vector<EC_POINT*> same_multi_g;
    std::vector<EC_POINT*> same_multi_h;
    std::vector<std::shared_ptr<BIGNUM>> sigma_a_storage;
    std::vector<std::shared_ptr<BIGNUM>> same_multi_r_A_storage;
    std::vector<BIGNUM*> same_scalar_a;
    std::vector<BIGNUM*> sigma_a;
    std::vector<BIGNUM*> same_multi_r_A;
    std::shared_ptr<BIGNUM> one = NewScalar(1);
    std::shared_ptr<BIGNUM> aggregate_beta_randomness = NewScalar(0);

    try
    {
        BuildPublicData(
            public_key,
            argument_commitment_key,
            beta_commitment_key,
            g_values,
            beta_commitments,
            sigma_ciphertexts,
            c_challenges,
            d_challenges,
            ct_g,
            aggregate_ct_g,
            weighted_sigma_ciphertexts,
            aggregate_beta_commitment,
            same_multi_g,
            same_multi_h);

        proof = Proof{};
        proof.witness.rho.reserve(count);
        proof.witness.aggregate_rho = NewScalar(0);
        sigma_a_storage.reserve(count);

        for (std::size_t i = 0; i < count; ++i)
        {
            ThrowIf(
                beta_commitment_randomness[i] == nullptr ||
                    sigma_encryption_randomness[i] == nullptr,
                "Sigma ciphertext argument witness randomness is not initialized");

            std::shared_ptr<BIGNUM> beta_i = ZZToBignum(beta[i]);
            std::shared_ptr<BIGNUM> beta_mod = NewScalar(0);
            std::shared_ptr<BIGNUM> product = NewScalar(0);
            std::shared_ptr<BIGNUM> rho_i = NewScalar(0);
            std::shared_ptr<BIGNUM> weighted_rho = NewScalar(0);
            std::shared_ptr<BIGNUM> weighted_beta_randomness = NewScalar(0);

            ThrowIf(
                BN_nnmod(beta_mod.get(), beta_i.get(), elgamal_.Order(), bn_ctx_) != 1 ||
                    BN_mod_mul(
                        product.get(),
                        beta_mod.get(),
                        sigma_encryption_randomness[i].get(),
                        elgamal_.Order(),
                        bn_ctx_) != 1 ||
                    BN_mod_sub(
                        rho_i.get(),
                        elgamal_.Order(),
                        product.get(),
                        elgamal_.Order(),
                        bn_ctx_) != 1 ||
                    BN_mod_mul(
                        weighted_rho.get(),
                        c_challenges[i].get(),
                        rho_i.get(),
                        elgamal_.Order(),
                        bn_ctx_) != 1 ||
                    BN_mod_add(
                        proof.witness.aggregate_rho.get(),
                        proof.witness.aggregate_rho.get(),
                        weighted_rho.get(),
                        elgamal_.Order(),
                        bn_ctx_) != 1 ||
                    BN_mod_mul(
                        weighted_beta_randomness.get(),
                        d_challenges[i].get(),
                        beta_commitment_randomness[i].get(),
                        elgamal_.Order(),
                        bn_ctx_) != 1 ||
                    BN_mod_add(
                        aggregate_beta_randomness.get(),
                        aggregate_beta_randomness.get(),
                        weighted_beta_randomness.get(),
                        elgamal_.Order(),
                        bn_ctx_) != 1,
                "Sigma ciphertext argument scalar arithmetic failed");

            proof.witness.rho.emplace_back(std::move(rho_i));
            sigma_a_storage.emplace_back(std::move(beta_mod));
        }

        std::shared_ptr<BIGNUM> same_scalar_k =
            ModNegate(proof.witness.aggregate_rho.get());
        same_scalar_a.emplace_back(one.get());

        same_scalar_.InitializePublicInstance(
            public_key,
            argument_commitment_key,
            std::vector<Ciphertext>{aggregate_ct_g},
            same_scalar_a,
            same_scalar_k.get(),
            proof.public_instance.same_scalar,
            proof.witness.same_scalar);

        const std::size_t target_size = NextPowerOfTwo(count + 3);
        const std::size_t r_A_count = target_size - count - 2;
        ThrowIf(
            r_A_count == 0 || same_multi_h.size() != r_A_count,
            "Sigma ciphertext argument SameMultiScalar padding size is invalid");

        same_multi_r_A_storage.emplace_back(std::move(aggregate_beta_randomness));
        for (std::size_t i = 1; i < r_A_count; ++i)
        {
            same_multi_r_A_storage.emplace_back(NewScalar(0));
        }

        for (const std::shared_ptr<BIGNUM>& value : sigma_a_storage)
        {
            sigma_a.emplace_back(value.get());
        }
        for (const std::shared_ptr<BIGNUM>& value : same_multi_r_A_storage)
        {
            same_multi_r_A.emplace_back(value.get());
        }

        same_multi_scalar_.InitializePublicInstance(
            argument_commitment_key,
            aggregate_beta_commitment,
            proof.public_instance.same_scalar.cm_u,
            proof.public_instance.same_scalar.cm_e,
            weighted_sigma_ciphertexts,
            same_multi_g,
            same_multi_h,
            sigma_a,
            same_multi_r_A,
            proof.witness.same_scalar.r_u,
            proof.witness.same_scalar.r_e,
            proof.public_instance.same_multi_scalar,
            proof.witness.same_multi_scalar);

        SameScalarArgument::Proof same_scalar_proof;
        SameMultiScalarArgument::Proof same_multi_scalar_proof;
        same_scalar_.CreateProof(
            argument_commitment_key,
            proof.public_instance.same_scalar,
            proof.witness.same_scalar,
            same_scalar_proof);
        same_multi_scalar_.CreateProof(
            argument_commitment_key,
            proof.public_instance.same_multi_scalar,
            proof.witness.same_multi_scalar,
            same_multi_scalar_proof);

        proof.public_instance.same_scalar =
            std::move(same_scalar_proof.public_instance);
        proof.public_instance.same_multi_scalar =
            std::move(same_multi_scalar_proof.public_instance);
        proof.witness.same_scalar = std::move(same_scalar_proof.witness);
        proof.witness.same_multi_scalar =
            std::move(same_multi_scalar_proof.witness);
        proof.message.public_instance = proof.public_instance;
        proof.message.same_scalar = std::move(same_scalar_proof.message);
        proof.message.same_multi_scalar =
            std::move(same_multi_scalar_proof.message);
    }
    catch (...)
    {
        FreePointVector(same_multi_g);
        FreePointVector(same_multi_h);
        throw;
    }

    FreePointVector(same_multi_g);
    FreePointVector(same_multi_h);
}

bool SigmaCiphertextArgument::VerifyProof(
    const PublicKey& public_key,
    const ArgumentCommitmentKey& argument_commitment_key,
    const BetaCommitmentKey& beta_commitment_key,
    const std::vector<GroupElement>& g_values,
    const std::vector<BetaCommitment>& beta_commitments,
    const std::vector<Ciphertext>& sigma_ciphertexts,
    const ProofMessage& proof_message) const
{
    std::vector<std::shared_ptr<BIGNUM>> c_challenges;
    std::vector<std::shared_ptr<BIGNUM>> d_challenges;
    std::vector<Ciphertext> ct_g;
    Ciphertext aggregate_ct_g;
    std::vector<Ciphertext> weighted_sigma_ciphertexts;
    BetaCommitment aggregate_beta_commitment;
    std::vector<EC_POINT*> same_multi_g;
    std::vector<EC_POINT*> same_multi_h;

    try
    {
        BuildPublicData(
            public_key,
            argument_commitment_key,
            beta_commitment_key,
            g_values,
            beta_commitments,
            sigma_ciphertexts,
            c_challenges,
            d_challenges,
            ct_g,
            aggregate_ct_g,
            weighted_sigma_ciphertexts,
            aggregate_beta_commitment,
            same_multi_g,
            same_multi_h);

        const bool matches = PublicInstanceMatches(
            public_key,
            argument_commitment_key,
            proof_message.public_instance,
            aggregate_ct_g,
            weighted_sigma_ciphertexts,
            aggregate_beta_commitment,
            same_multi_g,
            same_multi_h);
        const bool verifies = matches &&
            same_scalar_.VerifyProof(
                argument_commitment_key,
                proof_message.public_instance.same_scalar,
                proof_message.same_scalar) &&
            same_multi_scalar_.VerifyProof(
                argument_commitment_key,
                proof_message.public_instance.same_multi_scalar,
                proof_message.same_multi_scalar);

        FreePointVector(same_multi_g);
        FreePointVector(same_multi_h);
        return verifies;
    }
    catch (...)
    {
        FreePointVector(same_multi_g);
        FreePointVector(same_multi_h);
        return false;
    }
}

void SigmaCiphertextArgument::BuildPublicData(
    const PublicKey& public_key,
    const ArgumentCommitmentKey& argument_commitment_key,
    const BetaCommitmentKey& beta_commitment_key,
    const std::vector<GroupElement>& g_values,
    const std::vector<BetaCommitment>& beta_commitments,
    const std::vector<Ciphertext>& sigma_ciphertexts,
    std::vector<std::shared_ptr<BIGNUM>>& c_challenges,
    std::vector<std::shared_ptr<BIGNUM>>& d_challenges,
    std::vector<Ciphertext>& ct_g,
    Ciphertext& aggregate_ct_g,
    std::vector<Ciphertext>& weighted_sigma_ciphertexts,
    BetaCommitment& aggregate_beta_commitment,
    std::vector<EC_POINT*>& same_multi_g,
    std::vector<EC_POINT*>& same_multi_h) const
{
    const std::size_t count = sigma_ciphertexts.size();
    ThrowIf(
        !elgamal_.IsValidPublicKey(public_key) ||
            argument_commitment_key.group != elgamal_.Group() ||
            !elgamal_.IsValidCommitmentKey(beta_commitment_key) ||
            count == 0 ||
            g_values.size() < count ||
            beta_commitments.size() < count,
        "Sigma ciphertext argument public input is invalid");

    for (std::size_t i = 0; i < count; ++i)
    {
        ThrowIf(
            !elgamal_.IsValidGroupElement(g_values[i]) ||
                !elgamal_.IsValidCommitment(beta_commitments[i]) ||
                !elgamal_.IsValidCiphertext(sigma_ciphertexts[i]),
            "Sigma ciphertext argument public vector input is invalid");
    }

    GenerateChallenges(
        "PISCA sigma ciphertext c",
        public_key,
        beta_commitment_key,
        g_values,
        beta_commitments,
        sigma_ciphertexts,
        c_challenges);
    GenerateChallenges(
        "PISCA sigma ciphertext d",
        public_key,
        beta_commitment_key,
        g_values,
        beta_commitments,
        sigma_ciphertexts,
        d_challenges);

    ct_g.clear();
    weighted_sigma_ciphertexts.clear();
    FreePointVector(same_multi_g);
    FreePointVector(same_multi_h);
    ct_g.reserve(count);
    weighted_sigma_ciphertexts.reserve(count);
    same_multi_g.reserve(count);

    bool aggregate_ct_initialized = false;
    bool aggregate_commitment_initialized = false;
    for (std::size_t i = 0; i < count; ++i)
    {
        Ciphertext ct_g_i;
        ct_g_i.group = elgamal_.Group();
        ct_g_i.u = elgamal_.NewPoint();
        ct_g_i.e = DuplicatePoint(elgamal_.Group(), g_values[i].value);
        ThrowIf(
            ct_g_i.u == nullptr ||
                ct_g_i.e == nullptr ||
                EC_POINT_set_to_infinity(elgamal_.Group(), ct_g_i.u) != 1,
            "Sigma ciphertext argument ct_g allocation failed");
        ct_g.emplace_back(std::move(ct_g_i));

        Ciphertext weighted_ct_g;
        elgamal_.ScalarMultiply(
            public_key,
            weighted_ct_g,
            ct_g.back(),
            c_challenges[i].get());
        if (!aggregate_ct_initialized)
        {
            aggregate_ct_g = weighted_ct_g;
            aggregate_ct_initialized = true;
        }
        else
        {
            Ciphertext next;
            elgamal_.HomomorphicAdd(
                public_key,
                next,
                aggregate_ct_g,
                weighted_ct_g);
            aggregate_ct_g = std::move(next);
        }

        Ciphertext weighted_sigma;
        elgamal_.ScalarMultiply(
            public_key,
            weighted_sigma,
            sigma_ciphertexts[i],
            c_challenges[i].get());
        weighted_sigma_ciphertexts.emplace_back(std::move(weighted_sigma));

        EC_POINT* weighted_commitment = EC_POINT_new(elgamal_.Group());
        EC_POINT* weighted_g = EC_POINT_new(elgamal_.Group());
        ThrowIf(
            weighted_commitment == nullptr ||
                weighted_g == nullptr ||
                EC_POINT_mul(
                    elgamal_.Group(),
                    weighted_commitment,
                    nullptr,
                    beta_commitments[i].value,
                    d_challenges[i].get(),
                    bn_ctx_) != 1 ||
                EC_POINT_mul(
                    elgamal_.Group(),
                    weighted_g,
                    nullptr,
                    beta_commitment_key.g,
                    d_challenges[i].get(),
                    bn_ctx_) != 1,
            "Sigma ciphertext argument beta commitment aggregation failed");
        same_multi_g.emplace_back(weighted_g);

        if (!aggregate_commitment_initialized)
        {
            aggregate_beta_commitment.group = elgamal_.Group();
            aggregate_beta_commitment.value =
                DuplicatePoint(elgamal_.Group(), weighted_commitment);
            aggregate_commitment_initialized = true;
        }
        else
        {
            ThrowIf(
                EC_POINT_add(
                    elgamal_.Group(),
                    aggregate_beta_commitment.value,
                    aggregate_beta_commitment.value,
                    weighted_commitment,
                    bn_ctx_) != 1,
                "Sigma ciphertext argument beta commitment add failed");
        }
        EC_POINT_free(weighted_commitment);
    }

    const std::size_t r_A_count = NextPowerOfTwo(count + 3) - count - 2;
    ThrowIf(r_A_count == 0, "Sigma ciphertext argument padding size is invalid");
    same_multi_h.emplace_back(DuplicatePoint(elgamal_.Group(), beta_commitment_key.h));
    for (std::size_t i = 1; i < r_A_count; ++i)
    {
        std::shared_ptr<BIGNUM> scalar = NewScalar(static_cast<unsigned long>(i + 1));
        EC_POINT* padding_h = EC_POINT_new(elgamal_.Group());
        ThrowIf(
            padding_h == nullptr ||
                EC_POINT_mul(
                    elgamal_.Group(),
                    padding_h,
                    nullptr,
                    public_key.generator,
                    scalar.get(),
                    bn_ctx_) != 1,
            "Sigma ciphertext argument padding base generation failed");
        same_multi_h.emplace_back(padding_h);
    }
}

bool SigmaCiphertextArgument::PublicInstanceMatches(
    const PublicKey& public_key,
    const ArgumentCommitmentKey& argument_commitment_key,
    const PublicInstance& public_instance,
    const Ciphertext& aggregate_ct_g,
    const std::vector<Ciphertext>& weighted_sigma_ciphertexts,
    const BetaCommitment& aggregate_beta_commitment,
    const std::vector<EC_POINT*>& same_multi_g,
    const std::vector<EC_POINT*>& same_multi_h) const
{
    if (!elgamal_.IsValidPublicKey(public_key) ||
        public_instance.same_scalar.ciphertexts.size() != 1 ||
        public_instance.same_scalar.a.size() != 1 ||
        BN_is_one(public_instance.same_scalar.a[0]) != 1 ||
        !CiphertextsEqual(
            public_instance.same_scalar.ciphertexts[0],
            aggregate_ct_g) ||
        !PointsEqual(public_instance.same_scalar.u, aggregate_ct_g.u) ||
        !PointsEqual(public_instance.same_scalar.e, aggregate_ct_g.e) ||
        !PointsEqual(
            public_instance.same_scalar.u_a_sum,
            public_key.generator) ||
        !PointsEqual(
            public_instance.same_scalar.e_a_sum,
            public_key.pk) ||
        public_instance.same_multi_scalar.ciphertexts.size() !=
            weighted_sigma_ciphertexts.size() ||
        public_instance.same_multi_scalar.g.size() != same_multi_g.size() ||
        public_instance.same_multi_scalar.h.size() != same_multi_h.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < weighted_sigma_ciphertexts.size(); ++i)
    {
        if (!CiphertextsEqual(
                public_instance.same_multi_scalar.ciphertexts[i],
                weighted_sigma_ciphertexts[i]))
        {
            return false;
        }
    }
    for (std::size_t i = 0; i < same_multi_g.size(); ++i)
    {
        if (!PointsEqual(public_instance.same_multi_scalar.g[i], same_multi_g[i]))
        {
            return false;
        }
    }
    for (std::size_t i = 0; i < same_multi_h.size(); ++i)
    {
        if (!PointsEqual(public_instance.same_multi_scalar.h[i], same_multi_h[i]))
        {
            return false;
        }
    }

    EC_POINT* expected_A_m = DuplicatePoint(
        elgamal_.Group(),
        aggregate_beta_commitment.value);
    const bool matches = expected_A_m != nullptr &&
        EC_POINT_add(
            elgamal_.Group(),
            expected_A_m,
            expected_A_m,
            public_instance.same_scalar.cm_u.first,
            bn_ctx_) == 1 &&
        EC_POINT_add(
            elgamal_.Group(),
            expected_A_m,
            expected_A_m,
            public_instance.same_scalar.cm_e.first,
            bn_ctx_) == 1 &&
        PointsEqual(expected_A_m, public_instance.same_multi_scalar.A_m) &&
        PointsEqual(
            public_instance.same_scalar.cm_u.second,
            public_instance.same_multi_scalar.cm_um) &&
        PointsEqual(
            public_instance.same_scalar.cm_e.second,
            public_instance.same_multi_scalar.cm_em) &&
        PointsEqual(argument_commitment_key.GU, public_instance.same_multi_scalar.GU) &&
        PointsEqual(argument_commitment_key.GE, public_instance.same_multi_scalar.GE) &&
        PointsEqual(argument_commitment_key.H, public_instance.same_multi_scalar.H);
    EC_POINT_free(expected_A_m);
    return matches;
}

void SigmaCiphertextArgument::GenerateChallenges(
    const char* label,
    const PublicKey& public_key,
    const BetaCommitmentKey& beta_commitment_key,
    const std::vector<GroupElement>& g_values,
    const std::vector<BetaCommitment>& beta_commitments,
    const std::vector<Ciphertext>& sigma_ciphertexts,
    std::vector<std::shared_ptr<BIGNUM>>& challenges) const
{
    const std::size_t count = sigma_ciphertexts.size();
    challenges.clear();
    challenges.reserve(count);

    std::string base(label);
    AppendPoint(base, public_key.generator);
    AppendPoint(base, public_key.pk);
    AppendPoint(base, beta_commitment_key.g);
    AppendPoint(base, beta_commitment_key.h);
    for (std::size_t i = 0; i < count; ++i)
    {
        AppendPoint(base, g_values[i].value);
        AppendPoint(base, beta_commitments[i].value);
        AppendPoint(base, sigma_ciphertexts[i].u);
        AppendPoint(base, sigma_ciphertexts[i].e);
    }

    for (std::size_t i = 0; i < count; ++i)
    {
        std::string transcript = base;
        transcript.append("#");
        transcript.append(std::to_string(i));
        std::array<std::uint8_t, ElGamalEnc::HashBytes> digest{};
        elgamal_.RandomOracle(digest, transcript);

        BIGNUM* value = BN_bin2bn(digest.data(), digest.size(), nullptr);
        ThrowIf(value == nullptr, "Sigma ciphertext argument challenge allocation failed");
        std::shared_ptr<BIGNUM> challenge(value, BN_clear_free);
        ThrowIf(
            BN_nnmod(challenge.get(), challenge.get(), elgamal_.Order(), bn_ctx_) != 1,
            "Sigma ciphertext argument challenge normalization failed");
        if (BN_is_zero(challenge.get()))
        {
            ThrowIf(
                BN_set_word(challenge.get(), 1) != 1,
                "Sigma ciphertext argument zero challenge adjustment failed");
        }
        challenges.emplace_back(std::move(challenge));
    }
}

void SigmaCiphertextArgument::AppendPoint(
    std::string& transcript,
    const EC_POINT* point) const
{
    ThrowIf(point == nullptr, "Sigma ciphertext argument transcript point is null");
    const std::size_t point_size = EC_POINT_point2oct(
        elgamal_.Group(),
        point,
        POINT_CONVERSION_COMPRESSED,
        nullptr,
        0,
        bn_ctx_);
    ThrowIf(point_size == 0, "Sigma ciphertext argument point serialization failed");
    const std::size_t offset = transcript.size();
    transcript.resize(offset + point_size);
    ThrowIf(
        EC_POINT_point2oct(
            elgamal_.Group(),
            point,
            POINT_CONVERSION_COMPRESSED,
            reinterpret_cast<unsigned char*>(&transcript[offset]),
            point_size,
            bn_ctx_) != point_size,
        "Sigma ciphertext argument point serialization failed");
}

void SigmaCiphertextArgument::AppendScalar(
    std::string& transcript,
    const BIGNUM* scalar) const
{
    ThrowIf(scalar == nullptr, "Sigma ciphertext argument transcript scalar is null");
    const int byte_count = BN_num_bytes(scalar);
    const std::size_t offset = transcript.size();
    transcript.resize(offset + static_cast<std::size_t>(byte_count));
    BN_bn2bin(
        scalar,
        reinterpret_cast<unsigned char*>(&transcript[offset]));
}

std::shared_ptr<BIGNUM> SigmaCiphertextArgument::ZZToBignum(
    const NTL::ZZ& value) const
{
    BIGNUM* result = nullptr;
    const std::string decimal = ToString(value);
    ThrowIf(
        BN_dec2bn(&result, decimal.c_str()) == 0,
        "Sigma ciphertext argument NTL integer conversion failed");
    return std::shared_ptr<BIGNUM>(result, BN_clear_free);
}

std::shared_ptr<BIGNUM> SigmaCiphertextArgument::NewScalar(
    unsigned long value) const
{
    BIGNUM* scalar = BN_new();
    ThrowIf(
        scalar == nullptr || BN_set_word(scalar, value) != 1,
        "Sigma ciphertext argument scalar allocation failed");
    return std::shared_ptr<BIGNUM>(scalar, BN_clear_free);
}

std::shared_ptr<BIGNUM> SigmaCiphertextArgument::ModNegate(
    const BIGNUM* value) const
{
    std::shared_ptr<BIGNUM> result = NewScalar(0);
    ThrowIf(
        BN_mod_sub(result.get(), elgamal_.Order(), value, elgamal_.Order(), bn_ctx_) != 1,
        "Sigma ciphertext argument modular negation failed");
    return result;
}

bool SigmaCiphertextArgument::CiphertextsEqual(
    const Ciphertext& left,
    const Ciphertext& right) const
{
    return left.group == right.group &&
        PointsEqual(left.u, right.u) &&
        PointsEqual(left.e, right.e);
}

bool SigmaCiphertextArgument::PointsEqual(
    const EC_POINT* left,
    const EC_POINT* right) const
{
    return left != nullptr &&
        right != nullptr &&
        EC_POINT_cmp(elgamal_.Group(), left, right, bn_ctx_) == 0;
}

std::size_t SigmaCiphertextArgument::NextPowerOfTwo(std::size_t value) const
{
    std::size_t result = 1;
    while (result < value)
    {
        result <<= 1;
    }
    return result;
}

void SigmaCiphertextArgument::FreePointVector(
    std::vector<EC_POINT*>& points) const
{
    for (EC_POINT* point : points)
    {
        EC_POINT_free(point);
    }
    points.clear();
}
