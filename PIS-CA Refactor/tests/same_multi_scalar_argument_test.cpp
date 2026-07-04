#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../Curdleproofs/ElGamalCommitment/ElGamalCommitment.h"
#include "../Curdleproofs/SameMultiScalar Argument/SameMultiScalarArgument.h"
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

bool ComputeMultiScalarSum(
    const EC_GROUP* group,
    const std::vector<EC_POINT*>& bases,
    const std::vector<BIGNUM*>& scalars,
    EC_POINT* result)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    PointPtr term(EC_POINT_new(group), EC_POINT_free);
    if (ctx == nullptr || term == nullptr ||
        bases.size() != scalars.size() ||
        EC_POINT_set_to_infinity(group, result) != 1)
    {
        return false;
    }

    for (std::size_t i = 0; i < bases.size(); ++i)
    {
        if (bases[i] == nullptr ||
            scalars[i] == nullptr ||
            EC_POINT_mul(group, term.get(), nullptr, bases[i], scalars[i], ctx.get()) != 1 ||
            EC_POINT_add(group, result, result, term.get(), ctx.get()) != 1)
        {
            return false;
        }
    }
    return true;
}
}

int main()
{
    std::cout << "SameMultiScalarArgument test" << std::endl;

    bool all_passed = true;
    ElGamalEnc elgamal;
    ElGamalEnc::PublicKey public_key;
    ElGamalEnc::SecretKey secret_key;
    elgamal.GenerateKeys(public_key, secret_key);
    ElGamalCommitment commitment_scheme(elgamal);
    SameMultiScalarArgument::CommitmentKey commitment_key;
    commitment_scheme.Setup(commitment_key);
    SameMultiScalarArgument same_multi_scalar(elgamal);
    const EC_GROUP* group = commitment_key.group;

    constexpr std::size_t vector_size = 8;
    std::vector<PointPtr> owned_G;
    std::vector<PointPtr> owned_U;
    std::vector<PointPtr> owned_E;
    std::vector<EC_POINT*> G;
    std::vector<EC_POINT*> U;
    std::vector<EC_POINT*> E;
    for (std::size_t i = 0; i < vector_size; ++i)
    {
        owned_G.emplace_back(elgamal.NewPoint(), EC_POINT_free);
        owned_U.emplace_back(elgamal.NewPoint(), EC_POINT_free);
        owned_E.emplace_back(elgamal.NewPoint(), EC_POINT_free);
        elgamal.GenerateRandomGroupElement(owned_G.back().get());
        elgamal.GenerateRandomGroupElement(owned_U.back().get());
        elgamal.GenerateRandomGroupElement(owned_E.back().get());
        G.emplace_back(owned_G.back().get());
        U.emplace_back(owned_U.back().get());
        E.emplace_back(owned_E.back().get());
    }

    BNPtr x0 = MakeScalar(2);
    BNPtr x1 = MakeScalar(3);
    BNPtr x2 = MakeScalar(5);
    BNPtr x3 = MakeScalar(7);
    BNPtr x4 = MakeScalar(11);
    BNPtr x5 = MakeScalar(13);
    BNPtr r_u = MakeScalar(17);
    BNPtr r_e = MakeScalar(19);
    std::vector<BIGNUM*> sigma_a{x0.get(), x1.get(), x2.get(), x3.get()};
    std::vector<BIGNUM*> r_A{x4.get(), x5.get()};
    std::vector<BIGNUM*> x{
        x0.get(),
        x1.get(),
        x2.get(),
        x3.get(),
        x4.get(),
        x5.get(),
        r_u.get(),
        r_e.get()};
    std::vector<EC_POINT*> sub_g{G[0], G[1], G[2], G[3]};
    std::vector<EC_POINT*> sub_h{G[4], G[5]};

    std::vector<ElGamalEnc::Ciphertext> ciphertexts(sigma_a.size());
    for (std::size_t i = 0; i < ciphertexts.size(); ++i)
    {
        PointPtr message(elgamal.NewPoint(), EC_POINT_free);
        BNPtr plaintext = MakeScalar(31 + static_cast<unsigned long>(i));
        BNPtr enc_randomness = MakeScalar(41 + static_cast<unsigned long>(i));
        elgamal.EncodePlaintext(public_key, plaintext.get(), message.get());
        elgamal.EncryptWithRandomness(
            public_key,
            message.get(),
            enc_randomness.get(),
            ciphertexts[i]);
    }

    SameMultiScalarArgument::ScalarCommitment A_commitment;
    A_commitment.group = group;
    A_commitment.value = elgamal.NewPoint();
    std::vector<EC_POINT*> A_bases = sub_g;
    A_bases.insert(A_bases.end(), sub_h.begin(), sub_h.end());
    std::vector<BIGNUM*> A_scalars = sigma_a;
    A_scalars.insert(A_scalars.end(), r_A.begin(), r_A.end());
    ElGamalCommitment::Commitment cm_u;
    ElGamalCommitment::Commitment cm_e;
    std::vector<EC_POINT*> ciphertext_u;
    std::vector<EC_POINT*> ciphertext_e;
    for (const ElGamalEnc::Ciphertext& ciphertext : ciphertexts)
    {
        ciphertext_u.emplace_back(ciphertext.u);
        ciphertext_e.emplace_back(ciphertext.e);
    }
    PointPtr aggregate_u(elgamal.NewPoint(), EC_POINT_free);
    PointPtr aggregate_e(elgamal.NewPoint(), EC_POINT_free);
    all_passed = ExpectTrue(
        ComputeMultiScalarSum(group, A_bases, A_scalars, A_commitment.value) &&
            ComputeMultiScalarSum(group, ciphertext_u, sigma_a, aggregate_u.get()) &&
            ComputeMultiScalarSum(group, ciphertext_e, sigma_a, aggregate_e.get()),
        "Test inputs derive A and ciphertext aggregates from the witness") &&
        all_passed;
    commitment_scheme.CommitWithRandomness(
        commitment_key,
        commitment_key.GU,
        aggregate_u.get(),
        r_u.get(),
        cm_u);
    commitment_scheme.CommitWithRandomness(
        commitment_key,
        commitment_key.GE,
        aggregate_e.get(),
        r_e.get(),
        cm_e);

    SameMultiScalarArgument::PublicInstance public_instance;
    SameMultiScalarArgument::Witness witness;
    same_multi_scalar.InitializePublicInstance(
        commitment_key,
        A_commitment,
        cm_u,
        cm_e,
        ciphertexts,
        sub_g,
        sub_h,
        sigma_a,
        r_A,
        r_u.get(),
        r_e.get(),
        public_instance,
        witness);

    PointPtr expected_A(elgamal.NewPoint(), EC_POINT_free);
    PointPtr expected_U(elgamal.NewPoint(), EC_POINT_free);
    PointPtr expected_E(elgamal.NewPoint(), EC_POINT_free);
    CtxPtr expected_ctx(BN_CTX_new(), BN_CTX_free);
    EC_POINT_copy(expected_A.get(), A_commitment.value);
    EC_POINT_add(group, expected_A.get(), expected_A.get(), cm_u.first, expected_ctx.get());
    EC_POINT_add(group, expected_A.get(), expected_A.get(), cm_e.first, expected_ctx.get());
    EC_POINT_copy(expected_U.get(), cm_u.second);
    EC_POINT_copy(expected_E.get(), cm_e.second);
    all_passed = ExpectTrue(
        public_instance.group == group &&
            public_instance.G.size() == vector_size &&
            public_instance.U.size() == vector_size &&
            public_instance.E.size() == vector_size &&
            witness.x.size() == vector_size &&
            expected_ctx != nullptr &&
            PointsEqual(group, public_instance.A_m, expected_A.get()) &&
            PointsEqual(group, public_instance.cm_um, expected_U.get()) &&
            PointsEqual(group, public_instance.cm_em, expected_E.get()) &&
            BN_cmp(witness.x[0], x0.get()) == 0 &&
            witness.sigma_a.size() == sigma_a.size() &&
            witness.r_A.size() == r_A.size() &&
            BN_cmp(witness.r_A[0], x4.get()) == 0 &&
            BN_cmp(witness.r_u, r_u.get()) == 0,
        "InitializePublicInstance derives aggregated commitments and witness") &&
        all_passed;

    SameMultiScalarArgument::Proof proof;
    same_multi_scalar.CreateProof(commitment_key, public_instance, witness, proof);
    all_passed = ExpectTrue(
            proof.message.B_A != nullptr &&
            proof.message.B_U != nullptr &&
            proof.message.B_E != nullptr &&
            proof.message.L_A.size() == 3 &&
            proof.message.R_A.size() == 3 &&
            proof.message.L_U.size() == 3 &&
            proof.message.R_U.size() == 3 &&
            proof.message.L_E.size() == 3 &&
            proof.message.R_E.size() == 3 &&
            proof.message.x != nullptr &&
            proof.message.r_h != nullptr,
        "CreateProof fills folding rounds and final responses") &&
        all_passed;

    all_passed = ExpectTrue(
        same_multi_scalar.VerifyProof(commitment_key, public_instance, proof.message),
        "VerifyProof accepts a freshly generated proof message") &&
        all_passed;

    all_passed = ExpectTrue(
        same_multi_scalar.VerifyProof(commitment_key, proof),
        "VerifyProof accepts a full proof object") &&
        all_passed;

    SameMultiScalarArgument::ProofMessage tampered_response(proof.message);
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    BN_add_word(tampered_response.x, 1);
    BN_nnmod(tampered_response.x, tampered_response.x, elgamal.Order(), ctx.get());
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !same_multi_scalar.VerifyProof(commitment_key, public_instance, tampered_response),
        "VerifyProof rejects a tampered x response") &&
        all_passed;

    SameMultiScalarArgument::PublicInstance copied_instance(public_instance);
    all_passed = ExpectTrue(
        copied_instance.G.size() == public_instance.G.size() &&
            copied_instance.G[0] != public_instance.G[0] &&
            PointsEqual(group, copied_instance.G[0], public_instance.G[0]) &&
            copied_instance.A_m != public_instance.A_m &&
            PointsEqual(group, copied_instance.A_m, public_instance.A_m),
        "PublicInstance copy constructor performs deep copies") &&
        all_passed;

    SameMultiScalarArgument::Witness moved_witness(std::move(witness));
    all_passed = ExpectTrue(
        moved_witness.x.size() == vector_size &&
            witness.x.empty() &&
            moved_witness.r_A.size() == r_A.size() &&
            witness.r_A.empty(),
        "Witness move constructor transfers ownership") &&
        all_passed;

    SameMultiScalarArgument::PublicInstance invalid_instance(public_instance);
    EC_POINT_free(invalid_instance.A_m);
    invalid_instance.A_m = nullptr;
    all_passed = ExpectTrue(
        !same_multi_scalar.VerifyProof(commitment_key, invalid_instance, proof.message),
        "VerifyProof rejects an invalid public instance") &&
        all_passed;

    if (!all_passed)
    {
        std::cerr << "SameMultiScalarArgument test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "SameMultiScalarArgument test passed" << std::endl;
    return EXIT_SUCCESS;
}
