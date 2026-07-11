#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <NTL/ZZ.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../Curdleproofs/ElGamalCommitment/ElGamalCommitment.h"
#include "../ElGamal/ElGamalEnc.h"
#include "../PIS-CA/SigmaCiphertextArgument.h"

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

std::shared_ptr<BIGNUM> MakeSharedScalar(unsigned long value)
{
    BIGNUM* scalar = BN_new();
    if (scalar == nullptr || BN_set_word(scalar, value) != 1)
    {
        BN_clear_free(scalar);
        throw std::runtime_error("test scalar allocation failed");
    }
    return std::shared_ptr<BIGNUM>(scalar, BN_clear_free);
}

bool ScalarsEqualMod(
    const BIGNUM* left,
    const BIGNUM* right,
    const BIGNUM* modulus)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    BNPtr left_mod(BN_new(), BN_clear_free);
    BNPtr right_mod(BN_new(), BN_clear_free);
    return ctx != nullptr &&
        left_mod != nullptr &&
        right_mod != nullptr &&
        BN_nnmod(left_mod.get(), left, modulus, ctx.get()) == 1 &&
        BN_nnmod(right_mod.get(), right, modulus, ctx.get()) == 1 &&
        BN_cmp(left_mod.get(), right_mod.get()) == 0;
}

std::shared_ptr<BIGNUM> ExpectedRho(
    const BIGNUM* beta,
    const BIGNUM* sigma_randomness,
    const BIGNUM* order)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    std::shared_ptr<BIGNUM> product(BN_new(), BN_clear_free);
    std::shared_ptr<BIGNUM> rho(BN_new(), BN_clear_free);
    if (ctx == nullptr ||
        product == nullptr ||
        rho == nullptr ||
        BN_mod_mul(product.get(), beta, sigma_randomness, order, ctx.get()) != 1 ||
        BN_mod_sub(rho.get(), order, product.get(), order, ctx.get()) != 1)
    {
        throw std::runtime_error("test rho computation failed");
    }
    return rho;
}

ElGamalEnc::GroupElement RandomGroupElement(const ElGamalEnc& elgamal)
{
    ElGamalEnc::GroupElement element;
    element.group = elgamal.Group();
    element.value = elgamal.NewPoint();
    if (element.value == nullptr)
    {
        throw std::runtime_error("test group element allocation failed");
    }
    elgamal.GenerateRandomGroupElement(element.value);
    return element;
}

ElGamalEnc::GroupElement ScalarMultiplyPoint(
    const ElGamalEnc& elgamal,
    const EC_POINT* point,
    const BIGNUM* scalar)
{
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    ElGamalEnc::GroupElement result;
    result.group = elgamal.Group();
    result.value = elgamal.NewPoint();
    if (ctx == nullptr ||
        result.value == nullptr ||
        EC_POINT_mul(
            elgamal.Group(),
            result.value,
            nullptr,
            point,
            scalar,
            ctx.get()) != 1)
    {
        throw std::runtime_error("test point scalar multiplication failed");
    }
    return result;
}

void BuildValidStatement(
    const ElGamalEnc& elgamal,
    const ElGamalEnc::PublicKey& public_key,
    const ElGamalEnc::CommitmentKey& beta_commitment_key,
    std::vector<ElGamalEnc::GroupElement>& g_values,
    std::vector<ElGamalEnc::Commitment>& beta_commitments,
    std::vector<std::shared_ptr<BIGNUM>>& beta_commitment_randomness,
    std::vector<NTL::ZZ>& beta,
    std::vector<ElGamalEnc::Ciphertext>& sigma_ciphertexts,
    std::vector<std::shared_ptr<BIGNUM>>& sigma_encryption_randomness)
{
    const unsigned long beta_values[] = {5, 7, 11};
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr)
    {
        throw std::runtime_error("test BN_CTX allocation failed");
    }

    for (unsigned long beta_value : beta_values)
    {
        std::shared_ptr<BIGNUM> beta_bn = MakeSharedScalar(beta_value);
        std::shared_ptr<BIGNUM> beta_randomness(BN_new(), BN_clear_free);
        std::shared_ptr<BIGNUM> sigma_randomness(BN_new(), BN_clear_free);
        if (beta_randomness == nullptr || sigma_randomness == nullptr)
        {
            throw std::runtime_error("test randomness allocation failed");
        }

        ElGamalEnc::Commitment beta_commitment;
        elgamal.GenerateCommitment(
            beta_commitment_key,
            beta_bn.get(),
            beta_randomness.get(),
            beta_commitment);

        BNPtr beta_inverse(BN_mod_inverse(nullptr, beta_bn.get(), elgamal.Order(), ctx.get()), BN_clear_free);
        if (beta_inverse == nullptr)
        {
            throw std::runtime_error("test beta inverse failed");
        }

        ElGamalEnc::GroupElement g_value = RandomGroupElement(elgamal);
        ElGamalEnc::GroupElement sigma =
            ScalarMultiplyPoint(elgamal, g_value.value, beta_inverse.get());

        ElGamalEnc::Ciphertext sigma_ciphertext;
        elgamal.Encrypt(
            public_key,
            sigma.value,
            sigma_randomness.get(),
            sigma_ciphertext);

        g_values.emplace_back(std::move(g_value));
        beta_commitments.emplace_back(std::move(beta_commitment));
        beta_commitment_randomness.emplace_back(std::move(beta_randomness));
        beta.emplace_back(NTL::ZZ(beta_value));
        sigma_ciphertexts.emplace_back(std::move(sigma_ciphertext));
        sigma_encryption_randomness.emplace_back(std::move(sigma_randomness));
    }
}
}

int main()
{
    std::cout << "SigmaCiphertextArgument test" << std::endl;

    bool all_passed = true;
    ElGamalEnc elgamal;
    ElGamalEnc::PublicKey public_key;
    ElGamalEnc::SecretKey secret_key;
    ElGamalEnc::CommitmentKey beta_commitment_key;
    elgamal.GenerateKeys(public_key, secret_key, beta_commitment_key);

    ElGamalCommitment argument_commitment_scheme(elgamal);
    ElGamalCommitment::CommitmentKey argument_commitment_key;
    argument_commitment_scheme.Setup(argument_commitment_key);

    std::vector<ElGamalEnc::GroupElement> g_values;
    std::vector<ElGamalEnc::Commitment> beta_commitments;
    std::vector<std::shared_ptr<BIGNUM>> beta_commitment_randomness;
    std::vector<NTL::ZZ> beta;
    std::vector<ElGamalEnc::Ciphertext> sigma_ciphertexts;
    std::vector<std::shared_ptr<BIGNUM>> sigma_encryption_randomness;
    BuildValidStatement(
        elgamal,
        public_key,
        beta_commitment_key,
        g_values,
        beta_commitments,
        beta_commitment_randomness,
        beta,
        sigma_ciphertexts,
        sigma_encryption_randomness);

    SigmaCiphertextArgument sigma_argument(elgamal);
    SigmaCiphertextArgument::Proof proof;
    sigma_argument.CreateProof(
        public_key,
        argument_commitment_key,
        beta_commitment_key,
        g_values,
        beta_commitments,
        beta_commitment_randomness,
        beta,
        sigma_ciphertexts,
        sigma_encryption_randomness,
        proof);

    all_passed &= ExpectTrue(
        sigma_argument.VerifyProof(
            public_key,
            argument_commitment_key,
            beta_commitment_key,
            g_values,
            beta_commitments,
            sigma_ciphertexts,
            proof.message),
        "valid sigma ciphertext argument verifies");

    all_passed &= ExpectTrue(
        proof.witness.rho.size() == beta.size() &&
            ScalarsEqualMod(
                proof.witness.rho[0].get(),
                ExpectedRho(
                    MakeScalar(5).get(),
                    sigma_encryption_randomness[0].get(),
                    elgamal.Order()).get(),
                elgamal.Order()),
        "rho witness equals -beta times sigma encryption randomness");

    std::vector<ElGamalEnc::Ciphertext> tampered_sigma_ciphertexts =
        sigma_ciphertexts;
    BNPtr two = MakeScalar(2);
    elgamal.ScalarMultiply(
        public_key,
        tampered_sigma_ciphertexts[0],
        sigma_ciphertexts[0],
        two.get());
    all_passed &= ExpectTrue(
        !sigma_argument.VerifyProof(
            public_key,
            argument_commitment_key,
            beta_commitment_key,
            g_values,
            beta_commitments,
            tampered_sigma_ciphertexts,
            proof.message),
        "verification rejects a tampered sigma ciphertext");

    std::vector<ElGamalEnc::Commitment> tampered_beta_commitments =
        beta_commitments;
    EC_POINT* shifted_commitment = EC_POINT_dup(
        tampered_beta_commitments[0].value,
        elgamal.Group());
    if (shifted_commitment == nullptr ||
        EC_POINT_add(
            elgamal.Group(),
            shifted_commitment,
            shifted_commitment,
            beta_commitment_key.g,
            CtxPtr(BN_CTX_new(), BN_CTX_free).get()) != 1)
    {
        EC_POINT_free(shifted_commitment);
        throw std::runtime_error("test beta commitment tamper failed");
    }
    EC_POINT_free(tampered_beta_commitments[0].value);
    tampered_beta_commitments[0].value = shifted_commitment;
    all_passed &= ExpectTrue(
        !sigma_argument.VerifyProof(
            public_key,
            argument_commitment_key,
            beta_commitment_key,
            g_values,
            tampered_beta_commitments,
            sigma_ciphertexts,
            proof.message),
        "verification rejects a tampered beta commitment");

    if (!all_passed)
    {
        return EXIT_FAILURE;
    }

    std::cout << "SigmaCiphertextArgument test passed" << std::endl;
    return EXIT_SUCCESS;
}
