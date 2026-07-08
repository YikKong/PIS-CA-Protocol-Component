#include <cstdlib>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../Curdleproofs/Curdleproofs.h"
#include "../Curdleproofs/ElGamalCommitment/ElGamalCommitment.h"
#include "../Curdleproofs/SameMultiScalar Argument/SameMultiScalarArgument.h"
#include "../Curdleproofs/SamePermutation Argument/SamePermutationArgument.h"
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

std::string ScalarHex(const BIGNUM* value)
{
    if (value == nullptr)
    {
        return "<null>";
    }

    char* hex = BN_bn2hex(value);
    if (hex == nullptr)
    {
        return "<encode failed>";
    }

    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::string PointHex(const EC_GROUP* group, const EC_POINT* point)
{
    if (group == nullptr || point == nullptr)
    {
        return "<null>";
    }

    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr)
    {
        return "<ctx failed>";
    }

    const std::size_t size = EC_POINT_point2oct(
        group,
        point,
        POINT_CONVERSION_COMPRESSED,
        nullptr,
        0,
        ctx.get());
    if (size == 0)
    {
        return "<encode failed>";
    }

    std::vector<unsigned char> encoded(size);
    if (EC_POINT_point2oct(
            group,
            point,
            POINT_CONVERSION_COMPRESSED,
            encoded.data(),
            encoded.size(),
            ctx.get()) != size)
    {
        return "<encode failed>";
    }

    std::ostringstream oss;
    for (unsigned char byte : encoded)
    {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return oss.str();
}

void PrintCiphertext(
    const EC_GROUP* group,
    const std::string& label,
    const ElGamalEnc::Ciphertext& ciphertext)
{
    std::cout << label << ".u = " << PointHex(group, ciphertext.u) << std::endl;
    std::cout << label << ".e = " << PointHex(group, ciphertext.e) << std::endl;
}

std::vector<std::string> DecryptCiphertextSet(
    const ElGamalEnc& elgamal,
    const ElGamalEnc::PublicKey& public_key,
    const ElGamalEnc::SecretKey& secret_key,
    const std::vector<ElGamalEnc::Ciphertext>& ciphertexts)
{
    std::vector<std::string> plaintexts;
    plaintexts.reserve(ciphertexts.size());
    for (const ElGamalEnc::Ciphertext& ciphertext : ciphertexts)
    {
        PointPtr plaintext(elgamal.NewPoint(), EC_POINT_free);
        elgamal.Decrypt(public_key, secret_key, ciphertext, plaintext.get());
        plaintexts.emplace_back(PointHex(elgamal.Group(), plaintext.get()));
    }
    return plaintexts;
}

void PrintPlaintexts(
    const std::string& label,
    const std::vector<std::string>& plaintexts)
{
    for (std::size_t i = 0; i < plaintexts.size(); ++i)
    {
        std::cout << label << "[" << i << "] = " << plaintexts[i] << std::endl;
    }
}
}

int main()
{
    std::cout << "Curdleproofs test" << std::endl;

    bool all_passed = true;
    ElGamalEnc elgamal;
    ElGamalEnc::PublicKey public_key;
    ElGamalEnc::SecretKey secret_key;
    elgamal.GenerateKeys(public_key, secret_key);

    ElGamalCommitment commitment_scheme(elgamal);
    ElGamalCommitment::CommitmentKey commitment_key;
    commitment_scheme.Setup(commitment_key);

    const EC_GROUP* group = elgamal.Group();
    std::vector<ElGamalEnc::Ciphertext> ciphertexts;
    ciphertexts.reserve(3);
    for (unsigned long value : {5UL, 7UL, 11UL})
    {
        BNPtr plaintext_scalar = MakeScalar(value);
        BNPtr encryption_randomness(BN_new(), BN_clear_free);
        PointPtr plaintext(elgamal.NewPoint(), EC_POINT_free);
        ElGamalEnc::Ciphertext ciphertext;
        elgamal.GenerateRandomScalar(encryption_randomness.get());
        elgamal.EncodePlaintext(public_key, plaintext_scalar.get(), plaintext.get());
        elgamal.EncryptWithRandomness(
            public_key,
            plaintext.get(),
            encryption_randomness.get(),
            ciphertext);
        ciphertexts.emplace_back(std::move(ciphertext));
    }

    Curdleproofs curdleproofs(elgamal);
    Curdleproofs::PublicInstance public_instance;
    Curdleproofs::Witness witness;
    Curdleproofs::Proof proof;

    curdleproofs.InitializePublicInstance(
        public_key,
        commitment_key,
        ciphertexts,
        public_instance,
        witness);

    all_passed = ExpectTrue(
        public_instance.output_ciphertexts.size() == ciphertexts.size() &&
            public_instance.same_scalar.ciphertexts.size() == ciphertexts.size() &&
            public_instance.same_permutation.a.size() == ciphertexts.size() &&
            public_instance.same_permutation.g.size() == ciphertexts.size() &&
            public_instance.same_multi_scalar.ciphertexts.size() == ciphertexts.size() &&
            witness.same_permutation.sigma_a.size() == ciphertexts.size() &&
            witness.same_multi_scalar.x.size() == 2 * ciphertexts.size() + 2,
        "InitializePublicInstance only needs public key, commitment key, and ciphertexts") &&
        all_passed;

    curdleproofs.CreateProof(
        commitment_key,
        public_instance,
        witness,
        proof);

    SameScalarArgument same_scalar(elgamal);
    SamePermutationArgument same_permutation(elgamal);
    SameMultiScalarArgument same_multi_scalar(elgamal);
    const bool same_scalar_result = same_scalar.VerifyProof(
        commitment_key,
        proof.public_instance.same_scalar,
        proof.message.same_scalar);
    const bool same_permutation_result =
        same_permutation.VerifySamePermutationProof(
            proof.public_instance.same_permutation,
            proof.message.same_permutation);
    const bool grand_product_result =
        same_permutation.VerifyGrandProductProof(
            proof.public_instance.same_permutation.grand_product,
            proof.public_instance.same_permutation.inner_product,
            proof.message.same_permutation.grand_product,
            proof.message.same_permutation.inner_product);
    const bool inner_product_result =
        same_permutation.VerifyInnerProductProof(
            proof.public_instance.same_permutation.inner_product,
            proof.message.same_permutation.inner_product);
    const bool same_multi_scalar_result = same_multi_scalar.VerifyProof(
        commitment_key,
        proof.public_instance.same_multi_scalar,
        proof.message.same_multi_scalar);
    const bool verify_result = curdleproofs.VerifyProof(commitment_key, proof);

    std::vector<std::string> input_plaintexts =
        DecryptCiphertextSet(elgamal, public_key, secret_key, ciphertexts);
    std::vector<std::string> output_plaintexts =
        DecryptCiphertextSet(
            elgamal,
            public_key,
            secret_key,
            proof.public_instance.output_ciphertexts);
    std::vector<std::string> sorted_input_plaintexts(input_plaintexts);
    std::vector<std::string> sorted_output_plaintexts(output_plaintexts);
    std::sort(sorted_input_plaintexts.begin(), sorted_input_plaintexts.end());
    std::sort(sorted_output_plaintexts.begin(), sorted_output_plaintexts.end());
    const bool plaintext_set_preserved =
        sorted_input_plaintexts == sorted_output_plaintexts;

    all_passed = ExpectTrue(
        verify_result,
        "VerifyProof accepts a freshly generated Curdleproofs proof") &&
        all_passed;
    all_passed = ExpectTrue(
        same_scalar_result,
        "SameScalar subproof verifies") &&
        all_passed;
    all_passed = ExpectTrue(
        same_permutation_result,
        "SamePermutation subproof verifies") &&
        all_passed;
    all_passed = ExpectTrue(
        grand_product_result,
        "GrandProduct internal proof verifies") &&
        all_passed;
    all_passed = ExpectTrue(
        inner_product_result,
        "InnerProduct internal proof verifies") &&
        all_passed;
    all_passed = ExpectTrue(
        same_multi_scalar_result,
        "SameMultiScalar subproof verifies") &&
        all_passed;
    all_passed = ExpectTrue(
        plaintext_set_preserved,
        "Output ciphertexts decrypt to the same plaintext set as input") &&
        all_passed;

    std::cout << "input ciphertext count = " << ciphertexts.size() << std::endl;
    std::cout << "output ciphertext count = "
              << proof.public_instance.output_ciphertexts.size() << std::endl;
    std::cout << "same permutation vector size = "
              << proof.public_instance.same_permutation.a.size() << std::endl;
    std::cout << "same multi scalar x size = "
              << proof.witness.same_multi_scalar.x.size() << std::endl;
    std::cout << "SameScalar r_u = "
              << ScalarHex(proof.witness.same_scalar.r_u) << std::endl;
    std::cout << "SameScalar r_e = "
              << ScalarHex(proof.witness.same_scalar.r_e) << std::endl;
    std::cout << "SamePermutation r_A = "
              << ScalarHex(proof.witness.same_permutation.r_A) << std::endl;
    std::cout << "SamePermutation r_M = "
              << ScalarHex(proof.witness.same_permutation.r_M) << std::endl;
    std::cout << "SamePermutation A = "
              << PointHex(group, proof.public_instance.same_permutation.A.value)
              << std::endl;
    std::cout << "SameScalar cm_u.first = "
              << PointHex(group, proof.public_instance.same_scalar.cm_u.first)
              << std::endl;
    std::cout << "SameScalar cm_e.first = "
              << PointHex(group, proof.public_instance.same_scalar.cm_e.first)
              << std::endl;
    std::cout << "SameScalar verify result = "
              << (same_scalar_result ? "true" : "false") << std::endl;
    std::cout << "SamePermutation verify result = "
              << (same_permutation_result ? "true" : "false") << std::endl;
    std::cout << "GrandProduct verify result = "
              << (grand_product_result ? "true" : "false") << std::endl;
    std::cout << "InnerProduct verify result = "
              << (inner_product_result ? "true" : "false") << std::endl;
    std::cout << "SameMultiScalar verify result = "
              << (same_multi_scalar_result ? "true" : "false") << std::endl;
    PrintPlaintexts("input plaintext", input_plaintexts);
    PrintPlaintexts("output plaintext", output_plaintexts);
    std::cout << "plaintext set preserved = "
              << (plaintext_set_preserved ? "true" : "false") << std::endl;
    if (!ciphertexts.empty())
    {
        PrintCiphertext(group, "input_ciphertexts[0]", ciphertexts[0]);
    }
    if (!proof.public_instance.output_ciphertexts.empty())
    {
        PrintCiphertext(
            group,
            "output_ciphertexts[0]",
            proof.public_instance.output_ciphertexts[0]);
    }
    std::cout << "final verify result = " << (verify_result ? "true" : "false")
              << std::endl;

    if (!all_passed)
    {
        std::cerr << "Curdleproofs test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Curdleproofs test passed" << std::endl;
    return EXIT_SUCCESS;
}
