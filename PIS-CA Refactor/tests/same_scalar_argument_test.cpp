#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../Curdleproofs/ElGamalCommitment/ElGamalCommitment.h"
#include "../Curdleproofs/SameSalar Argument/SameScalarArgument.h"
#include "../ElGamal/ElGamalEnc.h"

namespace
{
using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

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

BNPtr MakeScalar(unsigned long value)
{
    BNPtr scalar(BN_new(), BN_clear_free);
    if (scalar == nullptr || BN_set_word(scalar.get(), value) != 1)
    {
        throw std::runtime_error("test scalar allocation failed");
    }
    return scalar;
}

bool PointsEqual(
    const EC_GROUP* group,
    const EC_POINT* left,
    const EC_POINT* right)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    return group != nullptr &&
        left != nullptr &&
        right != nullptr &&
        ctx != nullptr &&
        EC_POINT_cmp(group, left, right, ctx.get()) == 0;
}

bool ComputeAggregateCiphertext(
    const EC_GROUP* group,
    const std::vector<ElGamalEnc::Ciphertext>& ciphertexts,
    const std::vector<BIGNUM*>& a,
    EC_POINT* aggregate_u,
    EC_POINT* aggregate_e)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    PointPtr term(EC_POINT_new(group), EC_POINT_free);
    if (ctx == nullptr || term == nullptr ||
        EC_POINT_set_to_infinity(group, aggregate_u) != 1 ||
        EC_POINT_set_to_infinity(group, aggregate_e) != 1)
    {
        return false;
    }

    for (std::size_t i = 0; i < ciphertexts.size(); ++i)
    {
        if (EC_POINT_mul(
                group,
                term.get(),
                nullptr,
                ciphertexts[i].u,
                a[i],
                ctx.get()) != 1 ||
            EC_POINT_add(group, aggregate_u, aggregate_u, term.get(), ctx.get()) != 1 ||
            EC_POINT_mul(
                group,
                term.get(),
                nullptr,
                ciphertexts[i].e,
                a[i],
                ctx.get()) != 1 ||
            EC_POINT_add(group, aggregate_e, aggregate_e, term.get(), ctx.get()) != 1)
        {
            return false;
        }
    }

    return true;
}

bool SumScalars(
    const std::vector<BIGNUM*>& a,
    const BIGNUM* order,
    BIGNUM* sum)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr || BN_set_word(sum, 0) != 1)
    {
        return false;
    }

    for (const BIGNUM* value : a)
    {
        if (BN_mod_add(sum, sum, value, order, ctx.get()) != 1)
        {
            return false;
        }
    }
    return true;
}

bool ComputeExpectedPublicPoints(
    const ElGamalEnc& enc,
    const ElGamalEnc::PublicKey& public_key,
    const std::vector<ElGamalEnc::Ciphertext>& ciphertexts,
    const std::vector<BIGNUM*>& a,
    const BIGNUM* k,
    EC_POINT* expected_u,
    EC_POINT* expected_e,
    EC_POINT* expected_u_a_sum,
    EC_POINT* expected_e_a_sum)
{
    const EC_GROUP* group = enc.Group();
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    BNPtr sum_a(BN_new(), BN_clear_free);
    if (ctx == nullptr || sum_a == nullptr ||
        !ComputeAggregateCiphertext(group, ciphertexts, a, expected_u, expected_e) ||
        !SumScalars(a, enc.Order(), sum_a.get()))
    {
        return false;
    }

    return EC_POINT_mul(
               group,
               expected_u_a_sum,
               nullptr,
               public_key.g,
               sum_a.get(),
               ctx.get()) == 1 &&
        EC_POINT_mul(
            group,
            expected_e_a_sum,
            nullptr,
            public_key.pk,
            sum_a.get(),
            ctx.get()) == 1 &&
        k != nullptr;
}
}

int main()
{
    std::cout << "SameScalarArgument test" << std::endl;

    bool all_passed = true;
    ElGamalEnc elgamal;
    ElGamalEnc::PublicKey public_key;
    ElGamalEnc::SecretKey secret_key;
    elgamal.GenerateKeys(public_key, secret_key);

    ElGamalCommitment commitment_scheme(elgamal);
    SameScalarArgument::CommitmentKey commitment_key;
    commitment_scheme.Setup(commitment_key);

    SameScalarArgument same_scalar(elgamal);
    const EC_GROUP* group = elgamal.Group();

    BNPtr k = MakeScalar(17);
    BNPtr a0 = MakeScalar(2);
    BNPtr a1 = MakeScalar(5);
    std::vector<BIGNUM*> a{a0.get(), a1.get()};

    BNPtr plaintext0 = MakeScalar(11);
    BNPtr plaintext1 = MakeScalar(19);
    BNPtr enc_randomness0 = MakeScalar(7);
    BNPtr enc_randomness1 = MakeScalar(13);
    PointPtr message0(elgamal.NewPoint(), EC_POINT_free);
    PointPtr message1(elgamal.NewPoint(), EC_POINT_free);
    std::vector<ElGamalEnc::Ciphertext> ciphertexts(2);
    elgamal.EncodePlaintext(public_key, plaintext0.get(), message0.get());
    elgamal.EncodePlaintext(public_key, plaintext1.get(), message1.get());
    elgamal.EncryptWithRandomness(
        public_key,
        message0.get(),
        enc_randomness0.get(),
        ciphertexts[0]);
    elgamal.EncryptWithRandomness(
        public_key,
        message1.get(),
        enc_randomness1.get(),
        ciphertexts[1]);

    SameScalarArgument::PublicInstance public_instance;
    SameScalarArgument::Witness witness;
    same_scalar.InitializePublicInstance(
        public_key,
        commitment_key,
        ciphertexts,
        a,
        k.get(),
        public_instance,
        witness);

    PointPtr expected_u(elgamal.NewPoint(), EC_POINT_free);
    PointPtr expected_e(elgamal.NewPoint(), EC_POINT_free);
    PointPtr expected_u_a_sum(elgamal.NewPoint(), EC_POINT_free);
    PointPtr expected_e_a_sum(elgamal.NewPoint(), EC_POINT_free);
    all_passed = ExpectTrue(
        expected_u &&
            expected_e &&
            expected_u_a_sum &&
            expected_e_a_sum &&
            ComputeExpectedPublicPoints(
                elgamal,
                public_key,
                ciphertexts,
                a,
                k.get(),
                expected_u.get(),
                expected_e.get(),
                expected_u_a_sum.get(),
                expected_e_a_sum.get()) &&
            public_instance.group == group &&
            public_instance.ciphertexts.size() == ciphertexts.size() &&
            public_instance.a.size() == a.size() &&
            PointsEqual(group, public_instance.u, expected_u.get()) &&
            PointsEqual(group, public_instance.e, expected_e.get()) &&
            PointsEqual(group, public_instance.u_a_sum, expected_u_a_sum.get()) &&
            PointsEqual(group, public_instance.e_a_sum, expected_e_a_sum.get()) &&
            witness.k != nullptr &&
            witness.r_u != nullptr &&
            witness.r_e != nullptr &&
            BN_cmp(witness.k, k.get()) == 0 &&
            commitment_scheme.IsValidCommitment(public_instance.cm_u) &&
            commitment_scheme.IsValidCommitment(public_instance.cm_e),
        "InitializePublicInstance derives public points, commitments, and witness") &&
        all_passed;

    SameScalarArgument::Proof proof;
    same_scalar.CreateProof(commitment_key, public_instance, witness, proof);
    all_passed = ExpectTrue(
        proof.message.k_response != nullptr &&
            proof.message.r_u_response != nullptr &&
            proof.message.r_e_response != nullptr &&
            commitment_scheme.IsValidCommitment(proof.message.random_u_commitment) &&
            commitment_scheme.IsValidCommitment(proof.message.random_e_commitment),
        "CreateProof fills random commitments and responses") &&
        all_passed;

    all_passed = ExpectTrue(
        same_scalar.VerifyProof(commitment_key, public_instance, proof.message),
        "VerifyProof accepts a freshly generated proof message") &&
        all_passed;

    all_passed = ExpectTrue(
        same_scalar.VerifyProof(commitment_key, proof),
        "VerifyProof accepts a full proof object") &&
        all_passed;

    SameScalarArgument::ProofMessage tampered_response(proof.message);
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    BN_add_word(tampered_response.k_response, 1);
    BN_nnmod(
        tampered_response.k_response,
        tampered_response.k_response,
        elgamal.Order(),
        ctx.get());
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !same_scalar.VerifyProof(commitment_key, public_instance, tampered_response),
        "VerifyProof rejects a tampered k response") &&
        all_passed;

    SameScalarArgument::ProofMessage tampered_commitment(proof.message);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_commitment.random_u_commitment.second,
                tampered_commitment.random_u_commitment.second,
                public_key.g,
                ctx.get()) == 1 &&
            !same_scalar.VerifyProof(
                commitment_key,
                public_instance,
                tampered_commitment),
        "VerifyProof rejects a tampered random commitment") &&
        all_passed;

    SameScalarArgument::PublicInstance copied_instance(public_instance);
    all_passed = ExpectTrue(
        PointsEqual(group, copied_instance.u, public_instance.u) &&
            copied_instance.u != public_instance.u &&
            PointsEqual(group, copied_instance.e, public_instance.e) &&
            copied_instance.e != public_instance.e &&
            copied_instance.a.size() == public_instance.a.size() &&
            copied_instance.a[0] != public_instance.a[0] &&
            BN_cmp(copied_instance.a[0], public_instance.a[0]) == 0,
        "PublicInstance copy constructor performs deep copies") &&
        all_passed;

    SameScalarArgument::Witness copied_witness(witness);
    all_passed = ExpectTrue(
        copied_witness.k != witness.k &&
            copied_witness.r_u != witness.r_u &&
            copied_witness.r_e != witness.r_e &&
            BN_cmp(copied_witness.k, witness.k) == 0 &&
            BN_cmp(copied_witness.r_u, witness.r_u) == 0 &&
            BN_cmp(copied_witness.r_e, witness.r_e) == 0,
        "Witness copy constructor performs deep copies") &&
        all_passed;

    SameScalarArgument::ProofMessage moved_message(std::move(tampered_response));
    all_passed = ExpectTrue(
        moved_message.k_response != nullptr &&
            tampered_response.k_response == nullptr &&
            tampered_response.r_u_response == nullptr &&
            tampered_response.r_e_response == nullptr,
        "ProofMessage move constructor transfers ownership") &&
        all_passed;

    SameScalarArgument::PublicInstance invalid_instance(public_instance);
    EC_POINT_free(invalid_instance.u);
    invalid_instance.u = nullptr;
    all_passed = ExpectTrue(
        !same_scalar.VerifyProof(commitment_key, invalid_instance, proof.message),
        "VerifyProof rejects an invalid public instance") &&
        all_passed;

    if (!all_passed)
    {
        std::cerr << "SameScalarArgument test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "SameScalarArgument test passed" << std::endl;
    return EXIT_SUCCESS;
}
