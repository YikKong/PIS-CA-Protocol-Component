#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <NTL/ZZ.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../PIS-CA/PISCAProtocol.h"

namespace
{
struct BNDeleter
{
    void operator()(BIGNUM* value) const
    {
        BN_clear_free(value);
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
using UniqueBNCTX = std::unique_ptr<BN_CTX, BNCTXDeleter>;

std::string PointToHex(const EC_GROUP* group, const EC_POINT* point)
{
    if (group == nullptr || point == nullptr)
    {
        return "invalid";
    }

    const size_t size = EC_POINT_point2oct(
        group,
        point,
        POINT_CONVERSION_COMPRESSED,
        nullptr,
        0,
        nullptr);
    if (size == 0)
    {
        return "invalid";
    }

    std::vector<unsigned char> encoded(size);
    if (EC_POINT_point2oct(
            group,
            point,
            POINT_CONVERSION_COMPRESSED,
            encoded.data(),
            encoded.size(),
            nullptr) != size)
    {
        return "invalid";
    }

    static constexpr char Hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(encoded.size() * 2);
    for (unsigned char byte : encoded)
    {
        result.push_back(Hex[byte >> 4]);
        result.push_back(Hex[byte & 0x0f]);
    }
    return result;
}

void PrintInputSet(
    const std::string& label,
    const std::vector<NTL::ZZ>& input)
{
    std::cout << label << " input set:" << std::endl;
    for (std::uint32_t i = 0; i < input.size(); ++i)
    {
        std::cout << "  [" << i << "] " << input[i] << std::endl;
    }
}

void PrintOutputElements(
    const std::string& label,
    const std::vector<ElGamalEnc::GroupElement>& outputs)
{
    std::cout << label << " (g^a_i)^(1/beta_i) set:" << std::endl;
    for (std::uint32_t i = 0; i < outputs.size(); ++i)
    {
        std::cout
            << "  [" << i << "] "
            << PointToHex(outputs[i].group, outputs[i].value)
            << std::endl;
    }
}

bool PointsEqual(
    const ElGamalEnc::GroupElement& left,
    const ElGamalEnc::GroupElement& right)
{
    if (left.group == nullptr ||
        right.group == nullptr ||
        left.value == nullptr ||
        right.value == nullptr)
    {
        return false;
    }

    UniqueBNCTX context(BN_CTX_new());
    if (!context)
    {
        return false;
    }

    return EC_GROUP_cmp(left.group, right.group, context.get()) == 0 &&
        EC_POINT_cmp(left.group, left.value, right.value, context.get()) == 0;
}

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

bool ExpectEqual(const NTL::ZZ& actual, const NTL::ZZ& expected, const std::string& case_name)
{
    if (actual == expected)
    {
        std::cout << "[PASS] " << case_name << std::endl;
        return true;
    }

    std::cerr << "[FAIL] " << case_name << std::endl;
    std::cerr << "  expected: " << expected << std::endl;
    std::cerr << "  actual:   " << actual << std::endl;
    return false;
}

std::vector<NTL::ZZ> SlottedPlaintext(
    const NTL::ZZ& value,
    std::uint32_t slot_index)
{
    std::vector<NTL::ZZ> plaintext(
        CamenischShoupEnc::PlaintextValuesPerCiphertext,
        NTL::ZZ(0));
    plaintext[slot_index % CamenischShoupEnc::PlaintextValuesPerCiphertext] =
        value;
    return plaintext;
}

UniqueBN ZZToBN(const NTL::ZZ& value)
{
    BIGNUM* result = nullptr;
    std::ostringstream stream;
    stream << value;
    if (BN_dec2bn(&result, stream.str().c_str()) == 0)
    {
        BN_clear_free(result);
        return UniqueBN(nullptr);
    }
    return UniqueBN(result);
}

bool ComputePiscaOutputElements(
    const BIGNUM* group_order,
    const std::vector<ElGamalEnc::GroupElement>& g_to_a_values,
    const std::vector<NTL::ZZ>& beta_values,
    std::uint32_t input_count,
    std::vector<ElGamalEnc::GroupElement>& outputs)
{
    if (g_to_a_values.size() < input_count ||
        beta_values.size() < input_count)
    {
        return false;
    }

    UniqueBNCTX context(BN_CTX_new());
    if (!context)
    {
        return false;
    }

    outputs.clear();
    outputs.reserve(input_count);
    for (std::uint32_t i = 0; i < input_count; ++i)
    {
        if (group_order == nullptr ||
            g_to_a_values[i].group == nullptr ||
            g_to_a_values[i].value == nullptr ||
            EC_POINT_is_on_curve(
                g_to_a_values[i].group,
                g_to_a_values[i].value,
                context.get()) != 1 ||
            EC_POINT_is_at_infinity(
                g_to_a_values[i].group,
                g_to_a_values[i].value) == 1)
        {
            return false;
        }

        UniqueBN beta(ZZToBN(beta_values[i]));
        UniqueBN beta_mod(BN_new());
        if (!beta || !beta_mod ||
            BN_nnmod(
                beta_mod.get(),
                beta.get(),
                group_order,
                context.get()) != 1 ||
            BN_is_zero(beta_mod.get()))
        {
            return false;
        }

        UniqueBN inverse(BN_mod_inverse(
            nullptr,
            beta_mod.get(),
            group_order,
            context.get()));
        if (!inverse)
        {
            return false;
        }

        ElGamalEnc::GroupElement output;
        output.group = g_to_a_values[i].group;
        output.value = EC_POINT_new(output.group);
        if (output.value == nullptr ||
            EC_POINT_mul(
                output.group,
                output.value,
                nullptr,
                g_to_a_values[i].value,
                inverse.get(),
                context.get()) != 1)
        {
            return false;
        }
        outputs.emplace_back(std::move(output));
    }
    return true;
}

bool SigmaCiphertextsDecryptCorrectly(
    const ElGamalEnc::SecretKey& secret_key,
    const std::vector<ElGamalEnc::Ciphertext>& ciphertexts,
    const std::vector<ElGamalEnc::GroupElement>& plaintexts)
{
    if (secret_key.sk == nullptr || ciphertexts.size() != plaintexts.size())
    {
        return false;
    }

    UniqueBNCTX context(BN_CTX_new());
    if (!context)
    {
        return false;
    }
    for (std::size_t i = 0; i < ciphertexts.size(); ++i)
    {
        const ElGamalEnc::Ciphertext& ciphertext = ciphertexts[i];
        const ElGamalEnc::GroupElement& plaintext = plaintexts[i];
        if (ciphertext.group == nullptr ||
            ciphertext.group != plaintext.group ||
            ciphertext.u == nullptr ||
            ciphertext.e == nullptr ||
            plaintext.value == nullptr)
        {
            return false;
        }

        std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> shared_secret(
            EC_POINT_new(ciphertext.group),
            EC_POINT_free);
        std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> decrypted(
            EC_POINT_dup(ciphertext.e, ciphertext.group),
            EC_POINT_free);
        if (!shared_secret || !decrypted ||
            EC_POINT_mul(
                ciphertext.group,
                shared_secret.get(),
                nullptr,
                ciphertext.u,
                secret_key.sk,
                context.get()) != 1 ||
            EC_POINT_invert(
                ciphertext.group,
                shared_secret.get(),
                context.get()) != 1 ||
            EC_POINT_add(
                ciphertext.group,
                decrypted.get(),
                decrypted.get(),
                shared_secret.get(),
                context.get()) != 1 ||
            EC_POINT_cmp(
                ciphertext.group,
                decrypted.get(),
                plaintext.value,
                context.get()) != 0)
        {
            return false;
        }
    }
    return true;
}

}

int main()
{
    std::cout << "PIS-CA protocol data-flow test" << std::endl;

    bool all_passed = true;

    PISCAProtocol protocol;
    PISCAProtocol::P1 p1;
    PISCAProtocol::P2 p2;

    protocol.Setup(p1, p2);

    all_passed = ExpectTrue(
        protocol.CamenischShoupParametersAreIndependent(p1, p2),
        "P1 and P2 use independent Camenisch-Shoup parameters") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.ElGamalBaseParametersAreShared(p1, p2),
        "P1 and P2 share ElGamal base and commitment parameters") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.ElGamalNonBaseParametersAreIndependent(p1, p2),
        "P1 and P2 use independent non-base ElGamal parameters") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.CommitmentKeysAreIndependent(p1, p2),
        "P1 and P2 use independent Camenisch-Shoup commitment keys") &&
        all_passed;
    all_passed = ExpectTrue(
        p1.k > 0 &&
            p2.k > 0,
        "P1 and P2 DOPRF keys are initialized") &&
        all_passed;

    all_passed = ExpectTrue(
        protocol.InitializeP1(
            std::vector<NTL::ZZ>{
                NTL::ZZ(10), NTL::ZZ(20), NTL::ZZ(30), NTL::ZZ(40)},
            std::vector<NTL::ZZ>{
                NTL::ZZ(7), NTL::ZZ(11), NTL::ZZ(13), NTL::ZZ(17)},
            p1),
        "P1 input accepts same-sized x and v sets") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.InitializeP2(
            std::vector<NTL::ZZ>{NTL::ZZ(15), NTL::ZZ(20), NTL::ZZ(40)},
            p2),
        "P2 input accepts y set") &&
        all_passed;
    all_passed = ExpectTrue(
        p1.input_commitments.size() == p1.input.size() &&
            p1.input_commitment_randomness.size() == p1.input.size(),
        "P1 stores Camenisch-Shoup commitments for x") &&
        all_passed;
    all_passed = ExpectTrue(
        p2.input_commitments.size() == p2.input.size() &&
            p2.input_commitment_randomness.size() == p2.input.size(),
        "P2 stores Camenisch-Shoup commitments for y") &&
        all_passed;

    CamenischShoupEnc commitment_checker;
    bool p1_slotted_commitments_match = true;
    for (std::uint32_t i = 0; i < p1.input.size(); ++i)
    {
        CamenischShoupEnc::Commitment recomputed;
        commitment_checker.GenerateCommitmentWithRandomness(
            p1.camenisch_shoup_public_key,
            p1.camenisch_shoup_commitment_key,
            SlottedPlaintext(p1.input[i], i),
            p1.input_commitment_randomness[i],
            recomputed);
        p1_slotted_commitments_match =
            p1_slotted_commitments_match &&
            recomputed == p1.input_commitments[i];
    }
    all_passed = ExpectTrue(
        p1_slotted_commitments_match,
        "P1 input commitments rotate Camenisch-Shoup generators by index") &&
        all_passed;

    bool p2_slotted_commitments_match = true;
    for (std::uint32_t i = 0; i < p2.input.size(); ++i)
    {
        CamenischShoupEnc::Commitment recomputed;
        commitment_checker.GenerateCommitmentWithRandomness(
            p2.camenisch_shoup_public_key,
            p2.camenisch_shoup_commitment_key,
            SlottedPlaintext(p2.input[i], i),
            p2.input_commitment_randomness[i],
            recomputed);
        p2_slotted_commitments_match =
            p2_slotted_commitments_match &&
            recomputed == p2.input_commitments[i];
    }
    all_passed = ExpectTrue(
        p2_slotted_commitments_match,
        "P2 input commitments rotate Camenisch-Shoup generators by index") &&
        all_passed;

    protocol.ExecuteRoundOne(p1, p2);
    protocol.ExecuteRoundOne(p2, p1);

    all_passed = ExpectTrue(
            p1.round_one.message.k_ciphertext.u > 0 &&
            p1.round_one.message.k_ciphertext.e.size() ==
                CamenischShoupEnc::CiphertextEComponentCount &&
            p1.round_one.message.k_commitments.size() ==
                CamenischShoupEnc::PlaintextValuesPerCiphertext &&
            p1.round_one.message.k_proof_message.challenges.size() == 1 &&
            p1.round_one.message.k_proof_message.plaintext_randomness_responses.size() ==
                1 &&
            p1.round_one.witness.k == p1.k &&
            p1.round_one.witness.encryption_randomness > 0 &&
            p1.round_one.witness.commitment_randomness.size() ==
                CamenischShoupEnc::PlaintextValuesPerCiphertext,
        "P1 creates round-one ciphertext, slotted commitments, and proof for k1") &&
        all_passed;
    all_passed = ExpectTrue(
        p2.round_one.message.k_ciphertext.u > 0 &&
            p2.round_one.message.k_ciphertext.e.size() ==
                CamenischShoupEnc::CiphertextEComponentCount &&
            p2.round_one.message.k_commitments.size() ==
                CamenischShoupEnc::PlaintextValuesPerCiphertext &&
            p2.round_one.message.k_proof_message.challenges.size() == 1 &&
            p2.round_one.message.k_proof_message.plaintext_randomness_responses.size() ==
                1 &&
            p2.round_one.witness.k == p2.k &&
            p2.round_one.witness.encryption_randomness > 0 &&
            p2.round_one.witness.commitment_randomness.size() ==
                CamenischShoupEnc::PlaintextValuesPerCiphertext,
        "P2 creates round-one ciphertext, slotted commitments, and proof for k2") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.VerifyRoundOne(p1, p2) &&
            protocol.VerifyRoundOne(p2, p1),
        "Round-one proofs verify for both reversed protocol roles") &&
        all_passed;

    CamenischShoupEnc direct_camenisch_shoup;
    CamenischShoupEncZKP direct_zkp(direct_camenisch_shoup);
    all_passed = ExpectTrue(
        !direct_zkp.VerifyEncProof(
            p1.camenisch_shoup_public_key,
            p2.camenisch_shoup_commitment_key,
            std::vector<CamenischShoupEnc::Ciphertext>{
                p1.round_one.message.k_ciphertext},
            p1.round_one.message.k_commitments,
            p1.round_one.message.k_proof_message),
        "Round-one slotted-commitment proof is not accepted as a generic Enc proof") &&
        all_passed;

    protocol.ExecuteRoundTwo(p1, p2);
    all_passed = ExpectTrue(
        p1.round_two.message.proof_message.base_ciphertext.u ==
            p2.round_one.message.k_ciphertext.u &&
            p1.round_two.message.proof_message.base_ciphertext.e ==
                p2.round_one.message.k_ciphertext.e &&
            !p1.round_two.message.proof_message.beta_ciphertexts.empty() &&
            p1.round_two.message.proof_message.g_to_a_values.size() ==
                p1.round_two.witness.a.size() &&
            p1.round_two.message.proof_message.random_g_to_a_values.size() ==
                CamenischShoupEnc::PlaintextValuesPerCiphertext,
        "P1 RoundTwo uses P2 round-one ciphertext as base and sends g^a values") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.VerifyRoundTwo(p1, p2),
        "P1 RoundTwo proof verifies against Camenisch-Shoup and ElGamal relations") &&
        all_passed;
    for (std::uint32_t i = 0; i < p1.input.size(); ++i)
    {
        all_passed = ExpectEqual(
            p1.round_two.witness.alpha[i],
            p1.round_two.witness.a[i] *
                (p1.round_two.witness.k + p1.round_two.witness.input[i]),
            "P1 RoundTwo witness alpha equals a * (k + input)") &&
            all_passed;
    }

    protocol.ExecuteRoundThree(p2, p1);
    all_passed = ExpectTrue(
        p2.round_three.message.proof_message.ciphertexts.size() ==
            p1.round_two.message.proof_message.beta_ciphertexts.size() &&
            !p2.round_three.message.proof_message.ciphertexts.empty() &&
            p2.round_three.message.proof_message.ciphertexts[0].u ==
                p1.round_two.message.proof_message.beta_ciphertexts[0].u &&
            p2.round_three.message.proof_message.ciphertexts[0].e ==
                p1.round_two.message.proof_message.beta_ciphertexts[0].e &&
            p2.round_three.message.proof_message.camenisch_shoup_beta_commitments.size() ==
                p2.round_three.message.proof_message.ciphertexts.size() &&
            p2.round_three.message.proof_message.elgamal_beta_commitments.size() ==
                p2.round_three.witness.proof.beta.size(),
        "P2 RoundThree decrypts P1 beta ciphertexts and commits to beta") &&
        all_passed;
    all_passed = ExpectTrue(
        p2.round_three.witness.gamma.size() == p1.input.size() &&
            p2.round_three.witness.sigma.size() == p1.input.size() &&
            p2.round_three.witness.sigma_encryption_randomness.size() ==
                p1.input.size() &&
            p2.round_three.message.sigma_ciphertexts.size() ==
                p1.input.size() &&
            SigmaCiphertextsDecryptCorrectly(
                p2.elgamal_secret_key,
                p2.round_three.message.sigma_ciphertexts,
                p2.round_three.witness.sigma),
        "P2 RoundThree encrypts sigma with P2 ElGamal public key") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.VerifyRoundThree(p2, p1),
        "P2 RoundThree proof verifies beta decryption, commitments, and sigma ciphertexts") &&
        all_passed;

    PISCAProtocol::P2 tampered_sigma_ciphertext_p2 = p2;
    tampered_sigma_ciphertext_p2.round_three.message.sigma_ciphertexts[0] =
        p2.round_three.message.sigma_ciphertexts[1];
    all_passed = ExpectTrue(
        !protocol.VerifyRoundThree(tampered_sigma_ciphertext_p2, p1),
        "Round-three verification rejects a tampered sigma ciphertext") &&
        all_passed;

    PISCAProtocol::P2 tampered_sigma_public_instance_p2 = p2;
    if (tampered_sigma_public_instance_p2.round_three.message
            .sigma_proof_message.public_instance.same_scalar.a[0] != nullptr)
    {
        BN_add_word(
            tampered_sigma_public_instance_p2.round_three.message
                .sigma_proof_message.public_instance.same_scalar.a[0],
            1);
    }
    all_passed = ExpectTrue(
        !protocol.VerifyRoundThree(tampered_sigma_public_instance_p2, p1),
        "Round-three verification binds the sigma proof public instance") &&
        all_passed;

    PISCAProtocol::P2 tampered_round_three_p2 = p2;
    tampered_round_three_p2.round_three.message.proof_message.beta_responses[0] +=
        NTL::ZZ(1);
    all_passed = ExpectTrue(
        !protocol.VerifyRoundThree(tampered_round_three_p2, p1),
        "Round-three verification rejects a tampered beta response") &&
        all_passed;

    protocol.ExecuteRoundTwo(p2, p1);
    all_passed = ExpectTrue(
        p2.round_two.message.proof_message.base_ciphertext.u ==
            p1.round_one.message.k_ciphertext.u &&
            p2.round_two.message.proof_message.base_ciphertext.e ==
                p1.round_one.message.k_ciphertext.e &&
            !p2.round_two.message.proof_message.beta_ciphertexts.empty() &&
            p2.round_two.message.proof_message.g_to_a_values.size() ==
                p2.round_two.witness.a.size(),
        "P2 RoundTwo uses P1 round-one ciphertext as base and sends g^a values") &&
        all_passed;
    all_passed = ExpectTrue(
        protocol.VerifyRoundTwo(p2, p1),
        "P2 RoundTwo proof verifies against Camenisch-Shoup and ElGamal relations") &&
        all_passed;

    protocol.ExecuteRoundThree(p1, p2);
    all_passed = ExpectTrue(
        protocol.VerifyRoundThree(p1, p2),
        "P1 RoundThree proof verifies beta decryption, commitments, and sigma ciphertexts") &&
        all_passed;
    all_passed = ExpectTrue(
        p1.round_three.message.sigma_ciphertexts.size() == p2.input.size() &&
            p1.round_three.message.sigma_proof_message.public_instance
                    .same_multi_scalar.ciphertexts.size() == p2.input.size(),
        "P1 RoundThree sends sigma ciphertexts and SameMultiScalar public input") &&
        all_passed;

    ElGamalEnc comparison_elgamal;
    std::vector<ElGamalEnc::GroupElement> p1_outputs;
    std::vector<ElGamalEnc::GroupElement> p2_outputs;
    all_passed = ExpectTrue(
        ComputePiscaOutputElements(
            comparison_elgamal.Order(),
            p1.round_two.message.proof_message.g_to_a_values,
            p2.round_three.witness.proof.beta,
            static_cast<std::uint32_t>(p1.input.size()),
            p1_outputs),
        "P1-side PIS-CA output group elements are computed from beta") &&
        all_passed;
    all_passed = ExpectTrue(
        ComputePiscaOutputElements(
            comparison_elgamal.Order(),
            p2.round_two.message.proof_message.g_to_a_values,
            p1.round_three.witness.proof.beta,
            static_cast<std::uint32_t>(p2.input.size()),
            p2_outputs),
        "P2-side PIS-CA output group elements are computed from beta") &&
        all_passed;

    PrintInputSet("P1", p1.input);
    PrintInputSet("P2", p2.input);
    PrintOutputElements("P1", p1_outputs);
    PrintOutputElements("P2", p2_outputs);

    const bool outputs_are_ready =
        p1_outputs.size() == p1.input.size() &&
        p2_outputs.size() == p2.input.size();
    std::uint32_t output_match_count = 0;
    std::uint32_t expected_match_count = 0;
    bool output_matches_are_input_matches = outputs_are_ready;
    for (std::uint32_t i = 0; outputs_are_ready && i < p1.input.size(); ++i)
    {
        for (std::uint32_t j = 0; j < p2.input.size(); ++j)
        {
            if (p1.input[i] == p2.input[j])
            {
                ++expected_match_count;
            }
            if (PointsEqual(p1_outputs[i], p2_outputs[j]))
            {
                ++output_match_count;
                std::cout
                    << "[MATCH] P1 index " << i
                    << " value " << p1.input[i]
                    << " == P2 index " << j
                    << " value " << p2.input[j]
                    << std::endl;
                if (p1.input[i] != p2.input[j])
                {
                    output_matches_are_input_matches = false;
                }
            }
        }
    }
    all_passed = ExpectTrue(
        outputs_are_ready &&
            output_match_count == expected_match_count &&
            output_matches_are_input_matches,
        "Bidirectional PIS-CA group outputs match exactly on shared inputs") &&
        all_passed;

    CamenischShoupEnc camenisch_shoup;
    std::vector<NTL::ZZ> decrypted_k1;
    std::vector<NTL::ZZ> decrypted_k2;
    camenisch_shoup.Decrypt(
        p1.camenisch_shoup_public_key,
        p1.camenisch_shoup_secret_key,
        p1.round_one.message.k_ciphertext,
        decrypted_k1);
    camenisch_shoup.Decrypt(
        p2.camenisch_shoup_public_key,
        p2.camenisch_shoup_secret_key,
        p2.round_one.message.k_ciphertext,
        decrypted_k2);

    all_passed = ExpectTrue(
        !decrypted_k1.empty() &&
            !decrypted_k2.empty(),
        "Round-one ciphertexts decrypt under each party's own keys") &&
        all_passed;
    if (!decrypted_k1.empty())
    {
        all_passed = ExpectEqual(
            decrypted_k1[0],
            p1.k,
            "P1 decrypts P1 round-one ciphertext to k1") &&
            all_passed;
        all_passed = ExpectTrue(
            decrypted_k1.size() == 1 ||
                decrypted_k1[1] != p1.k,
            "P1 round-one ciphertext carries k in the first slot only") &&
            all_passed;
    }
    if (!decrypted_k2.empty())
    {
        all_passed = ExpectEqual(
            decrypted_k2[0],
            p2.k,
            "P2 decrypts P2 round-one ciphertext to k2") &&
            all_passed;
        all_passed = ExpectTrue(
            decrypted_k2.size() == 1 ||
                decrypted_k2[1] != p2.k,
            "P2 round-one ciphertext carries k in the first slot only") &&
            all_passed;
    }

    bool p1_k_commitments_match = true;
    bool p2_k_commitments_match = true;
    for (std::uint32_t i = 0;
         i < CamenischShoupEnc::PlaintextValuesPerCiphertext;
         ++i)
    {
        CamenischShoupEnc::Commitment recomputed_k1_commitment;
        CamenischShoupEnc::Commitment recomputed_k2_commitment;
        camenisch_shoup.GenerateCommitmentWithRandomness(
            p1.camenisch_shoup_public_key,
            p2.camenisch_shoup_commitment_key,
            SlottedPlaintext(p1.k, i),
            p1.round_one.witness.commitment_randomness[i],
            recomputed_k1_commitment);
        camenisch_shoup.GenerateCommitmentWithRandomness(
            p2.camenisch_shoup_public_key,
            p1.camenisch_shoup_commitment_key,
            SlottedPlaintext(p2.k, i),
            p2.round_one.witness.commitment_randomness[i],
            recomputed_k2_commitment);
        p1_k_commitments_match = p1_k_commitments_match &&
            p1.round_one.message.k_commitments[i] == recomputed_k1_commitment;
        p2_k_commitments_match = p2_k_commitments_match &&
            p2.round_one.message.k_commitments[i] == recomputed_k2_commitment;
    }
    all_passed = ExpectTrue(
        p1_k_commitments_match && p2_k_commitments_match,
        "Round-one k commitments use g_i^k h^r_i with the opposite party commitment key") &&
        all_passed;

    PISCAProtocol::P1 tampered_p1 = p1;
    tampered_p1.round_one.message.k_proof_message.plaintext_randomness_responses[0] +=
        NTL::ZZ(1);
    all_passed = ExpectTrue(
        !protocol.VerifyRoundOne(tampered_p1, p2),
        "Round-one verification rejects a tampered P1 proof") &&
        all_passed;

    PISCAProtocol::P2 tampered_p2 = p2;
    tampered_p2.round_one.message.k_commitments[0].value += NTL::ZZ(1);
    all_passed = ExpectTrue(
        !protocol.VerifyRoundOne(tampered_p2, p1),
        "Round-one verification binds the P2 commitment to the proof") &&
        all_passed;

    PISCAProtocol::P1 invalid_p1_input;
    all_passed = ExpectTrue(
        !protocol.InitializeP1(
            std::vector<NTL::ZZ>{NTL::ZZ(1), NTL::ZZ(2)},
            std::vector<NTL::ZZ>{NTL::ZZ(9)},
            invalid_p1_input),
        "P1 input rejects mismatched x and v sizes") &&
        all_passed;

    if (!all_passed)
    {
        std::cerr << "PIS-CA protocol data-flow test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "PIS-CA protocol data-flow test passed" << std::endl;
    return EXIT_SUCCESS;
}
