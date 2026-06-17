#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <NTL/ZZ.h>

#include "../CamenischShoup/CamenischShoupEnc.h"
#include "../CamenischShoup/CamenischShoupEncZKP.h"

namespace
{
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

bool ExpectEqual(const std::vector<NTL::ZZ>& actual, const std::vector<NTL::ZZ>& expected, const std::string& case_name)
{
    if (actual == expected)
    {
        std::cout << "[PASS] " << case_name << std::endl;
        return true;
    }

    std::cerr << "[FAIL] " << case_name << std::endl;
    return false;
}
}

int main()
{
    CamenischShoupEnc enc;
    CamenischShoupEncZKP zkp(enc);

    CamenischShoupEnc::PublicKey public_key;
    CamenischShoupEnc::SecretKey secret_key;
    CamenischShoupEnc::CommitmentKey commitment_key;

    std::cout << "Camenisch-Shoup encryption ZKP full flow test" << std::endl;
    std::cout << "Generating keys, inputs, commitments, and proof..." << std::endl;

    bool all_passed = true;

    enc.Setup(public_key);
    enc.GenerateKeys(public_key, secret_key, commitment_key);
    enc.InitializeInputs(public_key, commitment_key);

    std::vector<NTL::ZZ> zkp_commitments;
    zkp.GenerateCommitments(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_commitment_randomness,
        zkp_commitments);
    all_passed = ExpectEqual(zkp_commitments, enc.input_commitments, "ZKP recomputes Enc input commitments") && all_passed;

    CamenischShoupEncZKP::Proof proof;
    zkp.CreateProof(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_ciphertexts,
        enc.input_encryption_randomness,
        enc.input_commitment_randomness,
        enc.input_commitments,
        proof);

    all_passed = ExpectEqual(proof.plaintexts, enc.input_plaintexts, "CreateProof stores Enc plaintext set") && all_passed;
    all_passed = ExpectTrue(proof.ciphertexts.size() == enc.input_ciphertexts.size(), "CreateProof stores Enc ciphertext set") && all_passed;
    all_passed = ExpectEqual(proof.encryption_randomness, enc.input_encryption_randomness, "CreateProof stores Enc encryption randomness set") && all_passed;
    all_passed = ExpectEqual(proof.commitment_randomness, enc.input_commitment_randomness, "CreateProof stores Enc commitment randomness set") && all_passed;
    all_passed = ExpectEqual(proof.commitments, enc.input_commitments, "CreateProof stores Enc commitment set") && all_passed;

    all_passed = ExpectTrue(proof.plaintext_randomness.size() == CamenischShoupEnc::PlaintextValuesPerCiphertext, "CreateProof stores plaintext mask") && all_passed;
    all_passed = ExpectTrue(proof.encryption_randomness_mask > 0, "CreateProof stores encryption randomness mask") && all_passed;
    all_passed = ExpectTrue(proof.commitment_randomness_mask > 0, "CreateProof stores commitment randomness mask") && all_passed;

    all_passed = ExpectTrue(proof.message.ciphertexts.size() == enc.input_ciphertexts.size(), "ProofMessage carries ciphertext set") && all_passed;
    all_passed = ExpectEqual(proof.message.commitments, enc.input_commitments, "ProofMessage carries commitment set") && all_passed;
    all_passed = ExpectTrue(proof.message.random_ciphertext.e.size() == CamenischShoupEnc::CiphertextEComponentCount, "ProofMessage carries random ciphertext") && all_passed;
    all_passed = ExpectTrue(proof.message.random_commitment > 0, "ProofMessage carries random commitment") && all_passed;
    all_passed = ExpectTrue(proof.message.challenges.size() == enc.input_ciphertexts.size(), "ProofMessage carries batch challenges") && all_passed;
    all_passed = ExpectTrue(proof.message.plaintext_randomness_responses.size() == CamenischShoupEnc::PlaintextValuesPerCiphertext, "ProofMessage carries plaintext response vector") && all_passed;
    all_passed = ExpectTrue(proof.message.commitment_randomness_response > 0, "ProofMessage carries commitment randomness response") && all_passed;
    all_passed = ExpectTrue(proof.message.encryption_randomness_response > 0, "ProofMessage carries encryption randomness response") && all_passed;

    all_passed = ExpectTrue(
        zkp.VerifyProof(public_key, commitment_key, proof.message),
        "VerifyProof accepts proof message generated from Enc inputs") && all_passed;
    all_passed = ExpectTrue(
        zkp.VerifyProof(public_key, commitment_key, enc.input_ciphertexts, enc.input_commitments, proof.message),
        "VerifyProof accepts proof message with external Enc inputs") && all_passed;

    CamenischShoupEncZKP::ProofMessage tampered_message = proof.message;
    tampered_message.plaintext_randomness_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyProof(public_key, commitment_key, tampered_message),
        "VerifyProof rejects tampered plaintext response") && all_passed;

    if (!all_passed)
    {
        std::cerr << "Camenisch-Shoup encryption ZKP full flow test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Camenisch-Shoup encryption ZKP full flow test passed" << std::endl;
    return EXIT_SUCCESS;
}
