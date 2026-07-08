#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../Curdleproofs/SamePermutation Argument/SamePermutationArgument.h"
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

bool VectorCommit(
    const EC_GROUP* group,
    const std::vector<EC_POINT*>& g,
    const EC_POINT* h,
    const std::vector<BIGNUM*>& values,
    const BIGNUM* randomness,
    EC_POINT* result)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    PointPtr term(EC_POINT_new(group), EC_POINT_free);
    if (ctx == nullptr ||
        term == nullptr ||
        g.size() != values.size() ||
        h == nullptr ||
        randomness == nullptr ||
        result == nullptr ||
        EC_POINT_set_to_infinity(group, result) != 1)
    {
        return false;
    }

    for (std::size_t i = 0; i < g.size(); ++i)
    {
        if (g[i] == nullptr ||
            values[i] == nullptr ||
            EC_POINT_mul(group, term.get(), nullptr, g[i], values[i], ctx.get()) != 1 ||
            EC_POINT_add(group, result, result, term.get(), ctx.get()) != 1)
        {
            return false;
        }
    }

    return EC_POINT_mul(group, term.get(), nullptr, h, randomness, ctx.get()) == 1 &&
        EC_POINT_add(group, result, result, term.get(), ctx.get()) == 1;
}
}

int main()
{
    std::cout << "SamePermutationArgument test" << std::endl;

    bool all_passed = true;
    ElGamalEnc elgamal;
    SamePermutationArgument same_permutation(elgamal);
    const EC_GROUP* group = elgamal.Group();

    constexpr std::size_t vector_size = 3;
    BNPtr a0 = MakeScalar(11);
    BNPtr a1 = MakeScalar(13);
    BNPtr a2 = MakeScalar(17);
    BNPtr r_A = MakeScalar(23);
    BNPtr r_M = MakeScalar(29);
    std::vector<BIGNUM*> a{a0.get(), a1.get(), a2.get()};
    std::vector<std::size_t> permutation{2, 0, 1};

    SamePermutationArgument::PublicInstance public_instance;
    SamePermutationArgument::Witness witness;
    same_permutation.InitializeSamePermutationProof(
        a,
        permutation,
        r_A.get(),
        r_M.get(),
        public_instance,
        witness);

    std::vector<BIGNUM*> expected_sigma_a{
        a2.get(),
        a0.get(),
        a1.get()};
    PointPtr expected_A(elgamal.NewPoint(), EC_POINT_free);
    PointPtr expected_M(elgamal.NewPoint(), EC_POINT_free);
    all_passed = ExpectTrue(
        VectorCommit(
            group,
            public_instance.g,
            public_instance.h,
            expected_sigma_a,
            r_A.get(),
            expected_A.get()) &&
            VectorCommit(
                group,
                public_instance.g,
                public_instance.h,
                witness.sigma_n,
                r_M.get(),
                expected_M.get()) &&
            public_instance.group == group &&
            public_instance.g.size() == vector_size &&
            public_instance.h != nullptr &&
            public_instance.grand_product.group == group &&
            public_instance.grand_product.g.size() == vector_size &&
            public_instance.grand_product.h != nullptr &&
            public_instance.inner_product.group == group &&
            public_instance.inner_product.H != nullptr &&
            public_instance.inner_product.h != nullptr &&
            public_instance.a.size() == vector_size &&
            public_instance.n.size() == vector_size &&
            witness.permutation == permutation &&
            witness.sigma_a.size() == vector_size &&
            witness.sigma_n.size() == vector_size &&
            BN_cmp(witness.sigma_a[0], a2.get()) == 0 &&
            BN_cmp(witness.sigma_a[2], a1.get()) == 0 &&
            BN_is_word(public_instance.n[0], 1) &&
            BN_is_word(public_instance.n[2], 3) &&
            BN_is_word(witness.sigma_n[0], 3) &&
            BN_is_word(witness.sigma_n[2], 2) &&
            PointsEqual(group, public_instance.A.value, expected_A.get()) &&
            PointsEqual(group, public_instance.M.value, expected_M.get()) &&
            PointsEqual(group, public_instance.grand_product.h, public_instance.h),
        "InitializeSamePermutationProof fills public instance and witness") &&
        all_passed;

    SamePermutationArgument::Proof proof;
    same_permutation.CreateSamePermutationProof(public_instance, witness, proof);
    all_passed = ExpectTrue(
        proof.public_instance.group == group &&
            proof.public_instance.grand_product.group == group &&
            proof.public_instance.grand_product.g.size() == vector_size &&
            proof.public_instance.grand_product.h != nullptr &&
            PointsEqual(group, proof.public_instance.grand_product.h, public_instance.h) &&
            proof.public_instance.grand_product.B.group == group &&
            proof.public_instance.grand_product.B.value != nullptr &&
            proof.public_instance.grand_product.p != nullptr &&
            proof.witness.grand_product.b.size() == vector_size &&
            proof.witness.grand_product.r_B != nullptr &&
            proof.public_instance.inner_product.group == group &&
            proof.public_instance.inner_product.G.size() == vector_size + 1 &&
            proof.public_instance.inner_product.G_prime.size() == vector_size + 1 &&
            proof.public_instance.inner_product.H != nullptr &&
            proof.public_instance.inner_product.h != nullptr &&
            proof.public_instance.inner_product.C.value != nullptr &&
            proof.public_instance.inner_product.D.value != nullptr &&
            proof.public_instance.inner_product.z != nullptr &&
            proof.witness.inner_product.c.size() == vector_size + 1 &&
            proof.witness.inner_product.d.size() == vector_size + 1 &&
            proof.message.group == group &&
            proof.message.grand_product.group == group &&
            proof.message.grand_product.B != nullptr &&
            proof.message.grand_product.C != nullptr &&
            proof.message.grand_product.r_p != nullptr &&
            proof.message.inner_product.group == group &&
            proof.message.inner_product.A != nullptr &&
            proof.message.inner_product.B != nullptr &&
            proof.message.inner_product.c != nullptr &&
            proof.message.inner_product.d != nullptr &&
            proof.message.inner_product.r_h != nullptr &&
            proof.message.inner_product.L.size() == 2 &&
            proof.message.inner_product.R.size() == 2 &&
            PointsEqual(
                group,
                proof.public_instance.grand_product.B.value,
                proof.message.grand_product.B) &&
            PointsEqual(
                group,
                proof.public_instance.inner_product.G.back(),
                proof.public_instance.grand_product.h) &&
            PointsEqual(
                group,
                proof.public_instance.inner_product.C.value,
                proof.message.grand_product.C),
        "CreateSamePermutationProof fills SamePerm, GrandProduct, and InnerProduct structures") &&
        all_passed;

    bool grand_product_generators_match = true;
    for (std::size_t i = 0; i < vector_size; ++i)
    {
        grand_product_generators_match =
            grand_product_generators_match &&
            PointsEqual(
                group,
                proof.public_instance.grand_product.g[i],
                public_instance.g[i]);
    }
    all_passed = ExpectTrue(
        grand_product_generators_match,
        "GrandProduct public instance reuses top-level g vector") &&
        all_passed;

    all_passed = ExpectTrue(
        same_permutation.VerifySamePermutationProof(
            proof.public_instance,
            proof.message),
        "VerifySamePermutationProof accepts a freshly generated proof message") &&
        all_passed;

    all_passed = ExpectTrue(
        same_permutation.VerifySamePermutationProof(proof),
        "VerifySamePermutationProof accepts a full proof object") &&
        all_passed;

    SamePermutationArgument::ProofMessage tampered_message(proof.message);
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_message.grand_product.B,
                tampered_message.grand_product.B,
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(
                proof.public_instance,
                tampered_message),
        "VerifySamePermutationProof rejects a tampered B") &&
        all_passed;

    SamePermutationArgument::Proof tampered_inner_message(proof);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_inner_message.message.inner_product.A,
                tampered_inner_message.message.inner_product.A,
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(tampered_inner_message),
        "VerifySamePermutationProof rejects a tampered inner proof message") &&
        all_passed;

    SamePermutationArgument::Proof tampered_inner_l(proof);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !tampered_inner_l.message.inner_product.L.empty() &&
            EC_POINT_add(
                group,
                tampered_inner_l.message.inner_product.L[0],
                tampered_inner_l.message.inner_product.L[0],
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(tampered_inner_l),
        "VerifySamePermutationProof rejects a tampered inner L") &&
        all_passed;

    SamePermutationArgument::Proof tampered_inner_c_response(proof);
    BN_add_word(tampered_inner_c_response.message.inner_product.c, 1);
    BN_nnmod(
        tampered_inner_c_response.message.inner_product.c,
        tampered_inner_c_response.message.inner_product.c,
        elgamal.Order(),
        ctx.get());
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !same_permutation.VerifySamePermutationProof(tampered_inner_c_response),
        "VerifySamePermutationProof rejects a tampered inner c response") &&
        all_passed;

    SamePermutationArgument::Proof tampered_inner_r_h(proof);
    BN_add_word(tampered_inner_r_h.message.inner_product.r_h, 1);
    BN_nnmod(
        tampered_inner_r_h.message.inner_product.r_h,
        tampered_inner_r_h.message.inner_product.r_h,
        elgamal.Order(),
        ctx.get());
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !same_permutation.VerifySamePermutationProof(tampered_inner_r_h),
        "VerifySamePermutationProof rejects a tampered inner r_h") &&
        all_passed;

    SamePermutationArgument::Proof tampered_inner_d(proof);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_inner_d.public_instance.inner_product.D.value,
                tampered_inner_d.public_instance.inner_product.D.value,
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(tampered_inner_d),
        "VerifySamePermutationProof rejects a tampered inner D") &&
        all_passed;

    SamePermutationArgument::Proof tampered_inner_z(proof);
    BN_add_word(tampered_inner_z.public_instance.inner_product.z, 1);
    BN_nnmod(
        tampered_inner_z.public_instance.inner_product.z,
        tampered_inner_z.public_instance.inner_product.z,
        elgamal.Order(),
        ctx.get());
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !same_permutation.VerifySamePermutationProof(tampered_inner_z),
        "VerifySamePermutationProof rejects a tampered inner z") &&
        all_passed;

    SamePermutationArgument::Proof tampered_p(proof);
    BN_add_word(tampered_p.public_instance.grand_product.p, 1);
    BN_nnmod(
        tampered_p.public_instance.grand_product.p,
        tampered_p.public_instance.grand_product.p,
        elgamal.Order(),
        ctx.get());
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !same_permutation.VerifySamePermutationProof(tampered_p),
        "VerifySamePermutationProof rejects a tampered GrandProduct p") &&
        all_passed;

    SamePermutationArgument::Proof tampered_c(proof);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_c.message.grand_product.C,
                tampered_c.message.grand_product.C,
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(tampered_c),
        "VerifySamePermutationProof rejects a tampered GrandProduct C") &&
        all_passed;

    SamePermutationArgument::Proof tampered_r_p(proof);
    BN_add_word(tampered_r_p.message.grand_product.r_p, 1);
    BN_nnmod(
        tampered_r_p.message.grand_product.r_p,
        tampered_r_p.message.grand_product.r_p,
        elgamal.Order(),
        ctx.get());
    all_passed = ExpectTrue(
        ctx != nullptr &&
            !same_permutation.VerifySamePermutationProof(tampered_r_p),
        "VerifySamePermutationProof rejects a tampered GrandProduct r_p") &&
        all_passed;

    SamePermutationArgument::Proof tampered_g(proof);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_g.public_instance.inner_product.G[0],
                tampered_g.public_instance.inner_product.G[0],
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(tampered_g),
        "VerifySamePermutationProof rejects a tampered G vector") &&
        all_passed;

    SamePermutationArgument::Proof tampered_g_prime(proof);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_g_prime.public_instance.inner_product.G_prime[0],
                tampered_g_prime.public_instance.inner_product.G_prime[0],
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(tampered_g_prime),
        "VerifySamePermutationProof rejects a tampered G prime") &&
        all_passed;

    SamePermutationArgument::Proof tampered_grand_h(proof);
    all_passed = ExpectTrue(
        ctx != nullptr &&
            EC_POINT_add(
                group,
                tampered_grand_h.public_instance.grand_product.h,
                tampered_grand_h.public_instance.grand_product.h,
                public_instance.g[0],
                ctx.get()) == 1 &&
            !same_permutation.VerifySamePermutationProof(tampered_grand_h),
        "VerifySamePermutationProof rejects mismatched GrandProduct h") &&
        all_passed;

    bool invalid_permutation_rejected = false;
    try
    {
        SamePermutationArgument::PublicInstance invalid_public;
        SamePermutationArgument::Witness invalid_witness;
        same_permutation.InitializeSamePermutationProof(
            a,
            std::vector<std::size_t>{0, 0, 2},
            r_A.get(),
            r_M.get(),
            invalid_public,
            invalid_witness);
    }
    catch (const std::runtime_error&)
    {
        invalid_permutation_rejected = true;
    }
    all_passed = ExpectTrue(
        invalid_permutation_rejected,
        "InitializeSamePermutationProof rejects an invalid permutation") &&
        all_passed;

    SamePermutationArgument::PublicInstance copied_instance(public_instance);
    all_passed = ExpectTrue(
        copied_instance.g.size() == public_instance.g.size() &&
            copied_instance.g[0] != public_instance.g[0] &&
            PointsEqual(group, copied_instance.g[0], public_instance.g[0]) &&
            copied_instance.A.value != public_instance.A.value &&
            PointsEqual(group, copied_instance.A.value, public_instance.A.value),
        "PublicInstance copy constructor performs deep copies") &&
        all_passed;

    SamePermutationArgument::Witness moved_witness(std::move(witness));
    all_passed = ExpectTrue(
        moved_witness.sigma_a.size() == vector_size &&
            moved_witness.sigma_n.size() == vector_size &&
            witness.sigma_a.empty() &&
            witness.sigma_n.empty() &&
            moved_witness.r_A != nullptr &&
            witness.r_A == nullptr,
        "Witness move constructor transfers ownership") &&
        all_passed;

    SamePermutationArgument::InnerProductPublicInstance copied_inner(
        proof.public_instance.inner_product);
    all_passed = ExpectTrue(
        copied_inner.G.size() == proof.public_instance.inner_product.G.size() &&
            copied_inner.G[0] != proof.public_instance.inner_product.G[0] &&
            copied_inner.G_prime[0] != proof.public_instance.inner_product.G_prime[0] &&
            copied_inner.H != proof.public_instance.inner_product.H &&
            copied_inner.h != proof.public_instance.inner_product.h &&
            PointsEqual(group, copied_inner.G[0], proof.public_instance.inner_product.G[0]) &&
            PointsEqual(
                group,
                copied_inner.G_prime[0],
                proof.public_instance.inner_product.G_prime[0]) &&
            PointsEqual(group, copied_inner.H, proof.public_instance.inner_product.H) &&
            PointsEqual(group, copied_inner.h, proof.public_instance.inner_product.h),
        "InnerProductPublicInstance copy constructor performs deep copies") &&
        all_passed;

    SamePermutationArgument::GrandProductProofMessage copied_grand_message(
        proof.message.grand_product);
    all_passed = ExpectTrue(
        copied_grand_message.B != proof.message.grand_product.B &&
            copied_grand_message.C != proof.message.grand_product.C &&
            copied_grand_message.r_p != proof.message.grand_product.r_p &&
            PointsEqual(group, copied_grand_message.B, proof.message.grand_product.B) &&
            PointsEqual(group, copied_grand_message.C, proof.message.grand_product.C) &&
            BN_cmp(copied_grand_message.r_p, proof.message.grand_product.r_p) == 0,
        "GrandProductProofMessage copy constructor performs deep copies") &&
        all_passed;

    if (!all_passed)
    {
        std::cerr << "SamePermutationArgument test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "SamePermutationArgument test passed" << std::endl;
    return EXIT_SUCCESS;
}
