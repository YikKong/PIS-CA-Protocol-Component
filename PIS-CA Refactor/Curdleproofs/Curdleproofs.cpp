#include "Curdleproofs.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <utility>

#include <openssl/rand.h>

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

void FreeBNVector(std::vector<BIGNUM*>& values)
{
    for (BIGNUM* value : values)
    {
        BN_clear_free(value);
    }
    values.clear();
}

void FreePointVector(std::vector<EC_POINT*>& points)
{
    for (EC_POINT* point : points)
    {
        EC_POINT_free(point);
    }
    points.clear();
}

bool IsPowerOfTwo(std::size_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

std::size_t NextPowerOfTwo(std::size_t value)
{
    std::size_t result = 1;
    while (result < value)
    {
        result <<= 1;
    }
    return result;
}
}

Curdleproofs::Curdleproofs(const ElGamalEnc& elgamal)
    : elgamal_(elgamal),
      same_scalar_(elgamal),
      same_permutation_(elgamal),
      same_multi_scalar_(elgamal),
      bn_ctx_(BN_CTX_new())
{
    ThrowIf(bn_ctx_ == nullptr, "Curdleproofs BN_CTX allocation failed");
}

Curdleproofs::~Curdleproofs()
{
    BN_CTX_free(bn_ctx_);
}

void Curdleproofs::GenerateChallengeVector(
    std::size_t size,
    std::vector<BIGNUM*>& challenge_vector) const
{
    ThrowIf(size == 0, "Curdleproofs challenge vector size is invalid");

    FreeBNVector(challenge_vector);
    challenge_vector.reserve(size);
    try
    {
        for (std::size_t i = 0; i < size; ++i)
        {
            BIGNUM* value = BN_new();
            ThrowIf(value == nullptr, "Curdleproofs challenge scalar allocation failed");
            elgamal_.GenerateRandomScalar(value);
            challenge_vector.emplace_back(value);
        }
    }
    catch (...)
    {
        FreeBNVector(challenge_vector);
        throw;
    }
}

void Curdleproofs::GeneratePermutation(
    std::size_t size,
    std::vector<std::size_t>& permutation) const
{
    ThrowIf(size == 0, "Curdleproofs permutation size is invalid");

    permutation.resize(size);
    for (std::size_t i = 0; i < size; ++i)
    {
        permutation[i] = i;
    }

    for (std::size_t i = size - 1; i > 0; --i)
    {
        std::uint64_t random_value = 0;
        ThrowIf(
            RAND_bytes(
                reinterpret_cast<unsigned char*>(&random_value),
                sizeof(random_value)) != 1,
            "Curdleproofs permutation randomness failed");
        const std::size_t j = static_cast<std::size_t>(random_value % (i + 1));
        std::swap(permutation[i], permutation[j]);
    }
}

void Curdleproofs::RerandomizeCiphertexts(
    const PublicKey& public_key,
    const std::vector<Ciphertext>& ciphertexts,
    BIGNUM* rerandomization_scalar,
    std::vector<Ciphertext>& rerandomized_ciphertexts) const
{
    const EC_GROUP* group = elgamal_.Group();
    ThrowIf(
        !elgamal_.IsValidPublicKey(public_key) ||
            ciphertexts.empty() ||
            rerandomization_scalar == nullptr,
        "Curdleproofs rerandomization input is invalid");

    elgamal_.GenerateRandomScalar(rerandomization_scalar);
    std::vector<Ciphertext> next;
    next.reserve(ciphertexts.size());

    EC_POINT* g_term = EC_POINT_new(group);
    EC_POINT* pk_term = EC_POINT_new(group);
    ThrowIf(
        g_term == nullptr ||
            pk_term == nullptr ||
            EC_POINT_mul(
                group,
                g_term,
                nullptr,
                public_key.generator,
                rerandomization_scalar,
                bn_ctx_) != 1 ||
            EC_POINT_mul(
                group,
                pk_term,
                nullptr,
                public_key.pk,
                rerandomization_scalar,
                bn_ctx_) != 1,
        "Curdleproofs rerandomization term computation failed");

    try
    {
        for (const Ciphertext& ciphertext : ciphertexts)
        {
            ThrowIf(
                ciphertext.group != group ||
                    !elgamal_.IsValidCiphertext(ciphertext),
                "Curdleproofs ciphertext input is invalid");

            Ciphertext randomized;
            randomized.group = group;
            randomized.u = EC_POINT_new(group);
            randomized.e = EC_POINT_new(group);
            ThrowIf(
                randomized.u == nullptr ||
                    randomized.e == nullptr ||
                    EC_POINT_copy(randomized.u, ciphertext.u) != 1 ||
                    EC_POINT_add(group, randomized.u, randomized.u, g_term, bn_ctx_) != 1 ||
                    EC_POINT_copy(randomized.e, ciphertext.e) != 1 ||
                    EC_POINT_add(group, randomized.e, randomized.e, pk_term, bn_ctx_) != 1,
                "Curdleproofs ciphertext rerandomization failed");
            next.emplace_back(std::move(randomized));
        }
    }
    catch (...)
    {
        EC_POINT_free(g_term);
        EC_POINT_free(pk_term);
        throw;
    }

    EC_POINT_free(g_term);
    EC_POINT_free(pk_term);
    rerandomized_ciphertexts = std::move(next);
}

void Curdleproofs::RerandomizeCiphertextsWithScalars(
    const PublicKey& public_key,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<BIGNUM*>& rerandomization_scalars,
    std::vector<Ciphertext>& rerandomized_ciphertexts) const
{
    const EC_GROUP* group = elgamal_.Group();
    ThrowIf(
        !elgamal_.IsValidPublicKey(public_key) ||
            ciphertexts.empty() ||
            ciphertexts.size() != rerandomization_scalars.size(),
        "Curdleproofs per-ciphertext rerandomization input is invalid");

    std::vector<Ciphertext> next;
    next.reserve(ciphertexts.size());
    EC_POINT* g_term = EC_POINT_new(group);
    EC_POINT* pk_term = EC_POINT_new(group);
    ThrowIf(
        g_term == nullptr || pk_term == nullptr,
        "Curdleproofs per-ciphertext rerandomization term allocation failed");

    try
    {
        for (std::size_t i = 0; i < ciphertexts.size(); ++i)
        {
            const Ciphertext& ciphertext = ciphertexts[i];
            const BIGNUM* scalar = rerandomization_scalars[i];
            ThrowIf(
                ciphertext.group != group ||
                    !elgamal_.IsValidCiphertext(ciphertext) ||
                    scalar == nullptr,
                "Curdleproofs per-ciphertext rerandomization vector input is invalid");

            Ciphertext randomized;
            randomized.group = group;
            randomized.u = EC_POINT_new(group);
            randomized.e = EC_POINT_new(group);
            ThrowIf(
                randomized.u == nullptr ||
                    randomized.e == nullptr ||
                    EC_POINT_mul(
                        group,
                        g_term,
                        nullptr,
                        public_key.generator,
                        scalar,
                        bn_ctx_) != 1 ||
                    EC_POINT_mul(
                        group,
                        pk_term,
                        nullptr,
                        public_key.pk,
                        scalar,
                        bn_ctx_) != 1 ||
                    EC_POINT_copy(randomized.u, ciphertext.u) != 1 ||
                    EC_POINT_add(group, randomized.u, randomized.u, g_term, bn_ctx_) != 1 ||
                    EC_POINT_copy(randomized.e, ciphertext.e) != 1 ||
                    EC_POINT_add(group, randomized.e, randomized.e, pk_term, bn_ctx_) != 1,
                "Curdleproofs per-ciphertext rerandomization failed");
            next.emplace_back(std::move(randomized));
        }
    }
    catch (...)
    {
        EC_POINT_free(g_term);
        EC_POINT_free(pk_term);
        throw;
    }

    EC_POINT_free(g_term);
    EC_POINT_free(pk_term);
    rerandomized_ciphertexts = std::move(next);
}

void Curdleproofs::PermuteCiphertexts(
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<std::size_t>& permutation,
    std::vector<Ciphertext>& permuted_ciphertexts) const
{
    ThrowIf(
        ciphertexts.empty() ||
            !IsValidPermutation(permutation, ciphertexts.size()),
        "Curdleproofs ciphertext permutation input is invalid");

    std::vector<Ciphertext> next;
    next.reserve(ciphertexts.size());
    for (std::size_t index : permutation)
    {
        next.emplace_back(ciphertexts[index]);
    }
    permuted_ciphertexts = std::move(next);
}

void Curdleproofs::InitializePublicInstance(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<Ciphertext>& ciphertexts,
    PublicInstance& public_instance,
    Witness& witness) const
{
    ThrowIf(
        !elgamal_.IsValidPublicKey(public_key) ||
            ciphertexts.empty() ||
            !IsPowerOfTwo(ciphertexts.size() + 1),
        "Curdleproofs initialization input is invalid");

    std::vector<BIGNUM*> challenge_vector;
    std::vector<std::size_t> permutation;
    std::vector<Ciphertext> rerandomized_ciphertexts;
    std::vector<Ciphertext> permuted_ciphertexts;
    std::vector<EC_POINT*> same_multi_h;
    std::vector<BIGNUM*> same_multi_r_A;
    BIGNUM* k = BN_new();
    BIGNUM* r_A = BN_new();
    BIGNUM* r_M = BN_new();
    ThrowIf(k == nullptr || r_A == nullptr || r_M == nullptr,
        "Curdleproofs initialization scalar allocation failed");

    try
    {
        GenerateChallengeVector(ciphertexts.size(), challenge_vector);
        GeneratePermutation(ciphertexts.size(), permutation);
        RerandomizeCiphertexts(public_key, ciphertexts, k, rerandomized_ciphertexts);
        elgamal_.GenerateRandomScalar(r_A);
        elgamal_.GenerateRandomScalar(r_M);

        PublicInstance next_public;
        Witness next_witness;

        same_scalar_.InitializePublicInstance(
            public_key,
            commitment_key,
            ciphertexts,
            challenge_vector,
            k,
            next_public.same_scalar,
            next_witness.same_scalar);

        same_permutation_.InitializeSamePermutationProof(
            challenge_vector,
            permutation,
            r_A,
            r_M,
            next_public.same_permutation,
            next_witness.same_permutation);

        PermuteCiphertexts(
            rerandomized_ciphertexts,
            permutation,
            permuted_ciphertexts);
        BuildRepeatedPointVector(
            next_public.same_permutation.h,
            ciphertexts.size(),
            same_multi_h);
        SplitScalar(
            next_witness.same_permutation.r_A,
            ciphertexts.size(),
            same_multi_r_A);

        same_multi_scalar_.InitializePublicInstance(
            commitment_key,
            next_public.same_permutation.A,
            next_public.same_scalar.cm_u,
            next_public.same_scalar.cm_e,
            permuted_ciphertexts,
            next_public.same_permutation.g,
            same_multi_h,
            next_witness.same_permutation.sigma_a,
            same_multi_r_A,
            next_witness.same_scalar.r_u,
            next_witness.same_scalar.r_e,
            next_public.same_multi_scalar,
            next_witness.same_multi_scalar);

        next_public.output_ciphertexts = permuted_ciphertexts;
        public_instance = std::move(next_public);
        witness = std::move(next_witness);
    }
    catch (...)
    {
        FreeBNVector(challenge_vector);
        FreePointVector(same_multi_h);
        FreeBNVector(same_multi_r_A);
        BN_clear_free(k);
        BN_clear_free(r_A);
        BN_clear_free(r_M);
        throw;
    }

    FreeBNVector(challenge_vector);
    FreePointVector(same_multi_h);
    FreeBNVector(same_multi_r_A);
    BN_clear_free(k);
    BN_clear_free(r_A);
    BN_clear_free(r_M);
}

void Curdleproofs::InitializeKnownRerandomizedShuffle(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<BIGNUM*>& rerandomization_scalars,
    const std::vector<std::size_t>& permutation,
    PublicInstance& public_instance,
    Witness& witness) const
{
    ThrowIf(
        !elgamal_.IsValidPublicKey(public_key) ||
            ciphertexts.empty() ||
            ciphertexts.size() != rerandomization_scalars.size() ||
            !IsValidPermutation(permutation, ciphertexts.size()),
        "Curdleproofs known-rerandomized shuffle input is invalid");

    std::vector<BIGNUM*> challenge_vector;
    std::vector<Ciphertext> rerandomized_ciphertexts;
    std::vector<Ciphertext> permuted_ciphertexts;
    std::vector<EC_POINT*> same_multi_h;
    std::vector<BIGNUM*> same_multi_r_A;
    BIGNUM* k = BN_new();
    BIGNUM* r_A = BN_new();
    BIGNUM* r_M = BN_new();
    BIGNUM* sum_a = BN_new();
    BIGNUM* weighted_rerandomization = BN_new();
    BIGNUM* term = BN_new();
    BIGNUM* inverse_sum_a = nullptr;
    ThrowIf(
        k == nullptr ||
            r_A == nullptr ||
            r_M == nullptr ||
            sum_a == nullptr ||
            weighted_rerandomization == nullptr ||
            term == nullptr,
        "Curdleproofs known-rerandomized shuffle scalar allocation failed");

    try
    {
        bool challenge_ok = false;
        for (std::size_t attempt = 0; attempt < 16 && !challenge_ok; ++attempt)
        {
            GenerateChallengeVector(ciphertexts.size(), challenge_vector);
            ThrowIf(
                BN_set_word(sum_a, 0) != 1 ||
                    BN_set_word(weighted_rerandomization, 0) != 1,
                "Curdleproofs known-rerandomized shuffle accumulator initialization failed");
            for (std::size_t i = 0; i < ciphertexts.size(); ++i)
            {
                ThrowIf(
                    rerandomization_scalars[i] == nullptr ||
                        BN_mod_add(
                            sum_a,
                            sum_a,
                            challenge_vector[i],
                            elgamal_.Order(),
                            bn_ctx_) != 1 ||
                        BN_mod_mul(
                            term,
                            challenge_vector[i],
                            rerandomization_scalars[i],
                            elgamal_.Order(),
                            bn_ctx_) != 1 ||
                        BN_mod_add(
                            weighted_rerandomization,
                            weighted_rerandomization,
                            term,
                            elgamal_.Order(),
                            bn_ctx_) != 1,
                    "Curdleproofs known-rerandomized shuffle scalar arithmetic failed");
            }

            BN_clear_free(inverse_sum_a);
            inverse_sum_a = BN_mod_inverse(nullptr, sum_a, elgamal_.Order(), bn_ctx_);
            challenge_ok = inverse_sum_a != nullptr;
        }
        ThrowIf(
            inverse_sum_a == nullptr ||
                BN_mod_mul(
                    k,
                    weighted_rerandomization,
                    inverse_sum_a,
                    elgamal_.Order(),
                    bn_ctx_) != 1,
            "Curdleproofs known-rerandomized shuffle aggregate scalar failed");

        RerandomizeCiphertextsWithScalars(
            public_key,
            ciphertexts,
            rerandomization_scalars,
            rerandomized_ciphertexts);
        elgamal_.GenerateRandomScalar(r_A);
        elgamal_.GenerateRandomScalar(r_M);

        PublicInstance next_public;
        Witness next_witness;

        same_scalar_.InitializePublicInstance(
            public_key,
            commitment_key,
            ciphertexts,
            challenge_vector,
            k,
            next_public.same_scalar,
            next_witness.same_scalar);

        same_permutation_.InitializeSamePermutationProof(
            challenge_vector,
            permutation,
            r_A,
            r_M,
            next_public.same_permutation,
            next_witness.same_permutation);

        PermuteCiphertexts(
            rerandomized_ciphertexts,
            permutation,
            permuted_ciphertexts);

        const std::size_t r_A_parts =
            NextPowerOfTwo(ciphertexts.size() + 3) - ciphertexts.size() - 2;
        BuildRepeatedPointVector(
            next_public.same_permutation.h,
            r_A_parts,
            same_multi_h);
        SplitScalar(
            next_witness.same_permutation.r_A,
            r_A_parts,
            same_multi_r_A);

        same_multi_scalar_.InitializePublicInstance(
            commitment_key,
            next_public.same_permutation.A,
            next_public.same_scalar.cm_u,
            next_public.same_scalar.cm_e,
            permuted_ciphertexts,
            next_public.same_permutation.g,
            same_multi_h,
            next_witness.same_permutation.sigma_a,
            same_multi_r_A,
            next_witness.same_scalar.r_u,
            next_witness.same_scalar.r_e,
            next_public.same_multi_scalar,
            next_witness.same_multi_scalar);

        next_public.output_ciphertexts = permuted_ciphertexts;
        public_instance = std::move(next_public);
        witness = std::move(next_witness);
    }
    catch (...)
    {
        FreeBNVector(challenge_vector);
        FreePointVector(same_multi_h);
        FreeBNVector(same_multi_r_A);
        BN_clear_free(k);
        BN_clear_free(r_A);
        BN_clear_free(r_M);
        BN_clear_free(sum_a);
        BN_clear_free(weighted_rerandomization);
        BN_clear_free(term);
        BN_clear_free(inverse_sum_a);
        throw;
    }

    FreeBNVector(challenge_vector);
    FreePointVector(same_multi_h);
    FreeBNVector(same_multi_r_A);
    BN_clear_free(k);
    BN_clear_free(r_A);
    BN_clear_free(r_M);
    BN_clear_free(sum_a);
    BN_clear_free(weighted_rerandomization);
    BN_clear_free(term);
    BN_clear_free(inverse_sum_a);
}

void Curdleproofs::CreateProof(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance,
    const Witness& witness,
    Proof& proof) const
{
    SameScalarArgument::Proof same_scalar_proof;
    SamePermutationArgument::Proof same_permutation_proof;
    SameMultiScalarArgument::Proof same_multi_scalar_proof;

    same_scalar_.CreateProof(
        commitment_key,
        public_instance.same_scalar,
        witness.same_scalar,
        same_scalar_proof);
    same_permutation_.CreateSamePermutationProof(
        public_instance.same_permutation,
        witness.same_permutation,
        same_permutation_proof);
    same_multi_scalar_.CreateProof(
        commitment_key,
        public_instance.same_multi_scalar,
        witness.same_multi_scalar,
        same_multi_scalar_proof);

    proof.public_instance.output_ciphertexts = public_instance.output_ciphertexts;
    proof.public_instance.same_scalar = std::move(same_scalar_proof.public_instance);
    proof.public_instance.same_permutation = std::move(same_permutation_proof.public_instance);
    proof.public_instance.same_multi_scalar =
        std::move(same_multi_scalar_proof.public_instance);
    proof.witness.same_scalar = std::move(same_scalar_proof.witness);
    proof.witness.same_permutation = std::move(same_permutation_proof.witness);
    proof.witness.same_multi_scalar = std::move(same_multi_scalar_proof.witness);
    proof.message.same_scalar = std::move(same_scalar_proof.message);
    proof.message.same_permutation = std::move(same_permutation_proof.message);
    proof.message.same_multi_scalar = std::move(same_multi_scalar_proof.message);
}

bool Curdleproofs::VerifyProof(
    const CommitmentKey& commitment_key,
    const PublicInstance& public_instance,
    const ProofMessage& proof_message) const
{
    return same_scalar_.VerifyProof(
               commitment_key,
               public_instance.same_scalar,
               proof_message.same_scalar) &&
        same_permutation_.VerifySamePermutationProof(
            public_instance.same_permutation,
            proof_message.same_permutation) &&
        same_multi_scalar_.VerifyProof(
            commitment_key,
            public_instance.same_multi_scalar,
            proof_message.same_multi_scalar);
}

bool Curdleproofs::VerifyProof(
    const CommitmentKey& commitment_key,
    const Proof& proof) const
{
    return VerifyProof(commitment_key, proof.public_instance, proof.message);
}

void Curdleproofs::SplitScalar(
    const BIGNUM* scalar,
    std::size_t parts,
    std::vector<BIGNUM*>& shares) const
{
    ThrowIf(scalar == nullptr || parts == 0, "Curdleproofs scalar split input is invalid");

    FreeBNVector(shares);
    shares.reserve(parts);
    BIGNUM* sum = BN_new();
    BIGNUM* last = BN_new();
    ThrowIf(
        sum == nullptr ||
            last == nullptr ||
            BN_set_word(sum, 0) != 1,
        "Curdleproofs scalar split allocation failed");

    try
    {
        for (std::size_t i = 0; i + 1 < parts; ++i)
        {
            BIGNUM* share = BN_new();
            ThrowIf(share == nullptr, "Curdleproofs scalar share allocation failed");
            elgamal_.GenerateRandomScalar(share);
            ThrowIf(
                BN_mod_add(sum, sum, share, elgamal_.Order(), bn_ctx_) != 1,
                "Curdleproofs scalar share sum failed");
            shares.emplace_back(share);
        }

        ThrowIf(
            BN_mod_sub(last, scalar, sum, elgamal_.Order(), bn_ctx_) != 1,
            "Curdleproofs scalar final share computation failed");
        shares.emplace_back(last);
        last = nullptr;
    }
    catch (...)
    {
        FreeBNVector(shares);
        BN_clear_free(sum);
        BN_clear_free(last);
        throw;
    }

    BN_clear_free(sum);
    BN_clear_free(last);
}

void Curdleproofs::BuildRepeatedPointVector(
    const EC_POINT* point,
    std::size_t size,
    std::vector<EC_POINT*>& points) const
{
    const EC_GROUP* group = elgamal_.Group();
    ThrowIf(
        point == nullptr ||
            size == 0 ||
            EC_POINT_is_on_curve(group, point, bn_ctx_) != 1,
        "Curdleproofs repeated point input is invalid");

    FreePointVector(points);
    points.reserve(size);
    try
    {
        for (std::size_t i = 0; i < size; ++i)
        {
            EC_POINT* copy = DuplicatePoint(group, point);
            ThrowIf(copy == nullptr, "Curdleproofs repeated point copy failed");
            points.emplace_back(copy);
        }
    }
    catch (...)
    {
        FreePointVector(points);
        throw;
    }
}

bool Curdleproofs::IsValidPermutation(
    const std::vector<std::size_t>& permutation,
    std::size_t size) const
{
    if (permutation.size() != size)
    {
        return false;
    }

    std::vector<bool> seen(size, false);
    for (std::size_t index : permutation)
    {
        if (index >= size || seen[index])
        {
            return false;
        }
        seen[index] = true;
    }
    return true;
}
