#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../Curdleproofs/ElGamalCommitment/ElGamalCommitment.h"
#include "../ElGamal/ElGamalEnc.h"

namespace
{
struct BNDeleter
{
    void operator()(BIGNUM* value) const
    {
        BN_clear_free(value);
    }
};

struct PointDeleter
{
    void operator()(EC_POINT* value) const
    {
        EC_POINT_free(value);
    }
};

struct BNCTXDeleter
{
    void operator()(BN_CTX* value) const
    {
        BN_CTX_free(value);
    }
};

using UniqueBN = std::unique_ptr<BIGNUM, BNDeleter>;
using UniquePoint = std::unique_ptr<EC_POINT, PointDeleter>;
using UniqueBNCTX = std::unique_ptr<BN_CTX, BNCTXDeleter>;

bool ExpectTrue(bool condition, const std::string& case_name)
{
    if (condition)
    {
        std::cout << "[PASS] " << case_name << std::endl;
        return true;
    }

    std::cerr << "[FAIL] " << case_name << std::endl;
    return false;
}

UniqueBN MakeScalar(unsigned long value)
{
    UniqueBN scalar(BN_new());
    if (scalar)
    {
        BN_set_word(scalar.get(), value);
    }
    return scalar;
}

bool PointsEqual(
    const EC_GROUP* group,
    const EC_POINT* left,
    const EC_POINT* right)
{
    if (group == nullptr || left == nullptr || right == nullptr)
    {
        return false;
    }

    UniqueBNCTX context(BN_CTX_new());
    if (!context)
    {
        return false;
    }

    return EC_POINT_cmp(group, left, right, context.get()) == 0;
}

bool ComputeExpectedCommitment(
    const EC_GROUP* group,
    const EC_POINT* generator,
    const EC_POINT* h,
    const EC_POINT* element,
    const BIGNUM* randomness,
    EC_POINT* expected_first,
    EC_POINT* expected_second)
{
    UniqueBNCTX context(BN_CTX_new());
    UniquePoint randomness_term(EC_POINT_new(group));
    if (!context || !randomness_term)
    {
        return false;
    }

    return EC_POINT_mul(
               group,
               expected_first,
               nullptr,
               generator,
               randomness,
               context.get()) == 1 &&
        EC_POINT_mul(
            group,
            randomness_term.get(),
            nullptr,
            h,
            randomness,
            context.get()) == 1 &&
        EC_POINT_add(
            group,
            expected_second,
            element,
            randomness_term.get(),
            context.get()) == 1;
}

bool AddScalars(
    const BIGNUM* left,
    const BIGNUM* right,
    const BIGNUM* order,
    BIGNUM* result)
{
    UniqueBNCTX context(BN_CTX_new());
    return context &&
        BN_mod_add(result, left, right, order, context.get()) == 1;
}

bool AddPoints(
    const EC_GROUP* group,
    const EC_POINT* left,
    const EC_POINT* right,
    EC_POINT* result)
{
    UniqueBNCTX context(BN_CTX_new());
    return context &&
        EC_POINT_add(group, result, left, right, context.get()) == 1;
}
}

int main()
{
    std::cout << "ElGamal commitment test" << std::endl;

    bool all_passed = true;
    ElGamalEnc elgamal;
    ElGamalCommitment commitment_scheme(elgamal);
    ElGamalCommitment::CommitmentKey commitment_key;

    commitment_scheme.Setup(commitment_key);
    all_passed = ExpectTrue(
        commitment_scheme.IsValidCommitmentKey(commitment_key) &&
            commitment_key.group == elgamal.Group(),
        "Setup creates GU, GE, and H in the ElGamal group") &&
        all_passed;

    const EC_GROUP* group = elgamal.Group();
    const EC_POINT* generator = EC_GROUP_get0_generator(group);
    UniqueBN r_a = MakeScalar(5);
    UniqueBN r_b = MakeScalar(7);
    UniqueBN scalar_a = MakeScalar(11);
    UniqueBN scalar_b = MakeScalar(13);
    UniquePoint element_a(EC_POINT_new(group));
    UniquePoint element_b(EC_POINT_new(group));
    UniqueBNCTX context(BN_CTX_new());
    all_passed = ExpectTrue(
        r_a && r_b && scalar_a && scalar_b &&
            element_a && element_b && context &&
            EC_POINT_mul(
                group,
                element_a.get(),
                nullptr,
                generator,
                scalar_a.get(),
                context.get()) == 1 &&
            EC_POINT_mul(
                group,
                element_b.get(),
                nullptr,
                generator,
                scalar_b.get(),
                context.get()) == 1,
        "Test group elements are initialized") &&
        all_passed;

    ElGamalCommitment::Commitment gu_commitment;
    commitment_scheme.CommitWithRandomness(
        commitment_key,
        commitment_key.GU,
        element_a.get(),
        r_a.get(),
        gu_commitment);
    UniquePoint expected_gu_first(EC_POINT_new(group));
    UniquePoint expected_gu_second(EC_POINT_new(group));
    all_passed = ExpectTrue(
        expected_gu_first && expected_gu_second &&
            ComputeExpectedCommitment(
                group,
                commitment_key.GU,
                commitment_key.H,
                element_a.get(),
                r_a.get(),
                expected_gu_first.get(),
                expected_gu_second.get()) &&
            PointsEqual(group, gu_commitment.first, expected_gu_first.get()) &&
            PointsEqual(group, gu_commitment.second, expected_gu_second.get()),
        "CommitWithRandomness computes (r * GU, T + r * H)") &&
        all_passed;

    ElGamalCommitment::Commitment ge_commitment;
    commitment_scheme.CommitWithRandomness(
        commitment_key,
        commitment_key.GE,
        element_b.get(),
        r_b.get(),
        ge_commitment);
    UniquePoint expected_ge_first(EC_POINT_new(group));
    UniquePoint expected_ge_second(EC_POINT_new(group));
    all_passed = ExpectTrue(
        expected_ge_first && expected_ge_second &&
            ComputeExpectedCommitment(
                group,
                commitment_key.GE,
                commitment_key.H,
                element_b.get(),
                r_b.get(),
                expected_ge_first.get(),
                expected_ge_second.get()) &&
            PointsEqual(group, ge_commitment.first, expected_ge_first.get()) &&
            PointsEqual(group, ge_commitment.second, expected_ge_second.get()),
        "CommitWithRandomness computes (r * GE, T + r * H)") &&
        all_passed;

    UniqueBN generated_randomness(BN_new());
    ElGamalCommitment::Commitment generated_commitment;
    commitment_scheme.Commit(
        commitment_key,
        commitment_key.GU,
        element_a.get(),
        generated_randomness.get(),
        generated_commitment);
    all_passed = ExpectTrue(
        generated_randomness &&
            BN_cmp(generated_randomness.get(), elgamal.Order()) < 0 &&
            commitment_scheme.IsValidCommitment(generated_commitment),
        "Commit generates randomness and a valid commitment") &&
        all_passed;

    ElGamalCommitment::Commitment gu_commitment_b;
    commitment_scheme.CommitWithRandomness(
        commitment_key,
        commitment_key.GU,
        element_b.get(),
        r_b.get(),
        gu_commitment_b);

    ElGamalCommitment::Commitment homomorphic_sum;
    commitment_scheme.Add(gu_commitment, gu_commitment_b, homomorphic_sum);

    UniquePoint element_sum(EC_POINT_new(group));
    UniqueBN randomness_sum(BN_new());
    ElGamalCommitment::Commitment expected_sum;
    all_passed = ExpectTrue(
        element_sum && randomness_sum &&
            AddPoints(
                group,
                element_a.get(),
                element_b.get(),
                element_sum.get()) &&
            AddScalars(
                r_a.get(),
                r_b.get(),
                elgamal.Order(),
                randomness_sum.get()),
        "Homomorphic test inputs are combined") &&
        all_passed;

    commitment_scheme.CommitWithRandomness(
        commitment_key,
        commitment_key.GU,
        element_sum.get(),
        randomness_sum.get(),
        expected_sum);
    all_passed = ExpectTrue(
        PointsEqual(group, homomorphic_sum.first, expected_sum.first) &&
            PointsEqual(group, homomorphic_sum.second, expected_sum.second),
        "Commit(A; r_A) + Commit(B; r_B) equals Commit(A + B; r_A + r_B)") &&
        all_passed;

    if (!all_passed)
    {
        std::cerr << "ElGamal commitment test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "ElGamal commitment test passed" << std::endl;
    return EXIT_SUCCESS;
}
