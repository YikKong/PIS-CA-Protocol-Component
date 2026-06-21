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
    zkp.CreateEncProof(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_ciphertexts,
        enc.input_encryption_randomness,
        enc.input_commitment_randomness,
        enc.input_commitments,
        proof);

    all_passed = ExpectEqual(proof.plaintexts, enc.input_plaintexts, "CreateEncProof stores Enc plaintext set") && all_passed;
    all_passed = ExpectTrue(proof.ciphertexts.size() == enc.input_ciphertexts.size(), "CreateEncProof stores Enc ciphertext set") && all_passed;
    all_passed = ExpectEqual(proof.encryption_randomness, enc.input_encryption_randomness, "CreateEncProof stores Enc encryption randomness set") && all_passed;
    all_passed = ExpectEqual(proof.commitment_randomness, enc.input_commitment_randomness, "CreateEncProof stores Enc commitment randomness set") && all_passed;
    all_passed = ExpectEqual(proof.commitments, enc.input_commitments, "CreateEncProof stores Enc commitment set") && all_passed;

    all_passed = ExpectTrue(proof.plaintext_randomness.size() == CamenischShoupEnc::PlaintextValuesPerCiphertext, "CreateEncProof stores plaintext mask") && all_passed;
    all_passed = ExpectTrue(proof.encryption_randomness_mask > 0, "CreateEncProof stores encryption randomness mask") && all_passed;
    all_passed = ExpectTrue(proof.commitment_randomness_mask > 0, "CreateEncProof stores commitment randomness mask") && all_passed;

    all_passed = ExpectTrue(proof.message.ciphertexts.size() == enc.input_ciphertexts.size(), "ProofMessage carries ciphertext set") && all_passed;
    all_passed = ExpectEqual(proof.message.commitments, enc.input_commitments, "ProofMessage carries commitment set") && all_passed;
    all_passed = ExpectTrue(proof.message.random_ciphertext.e.size() == CamenischShoupEnc::CiphertextEComponentCount, "ProofMessage carries random ciphertext") && all_passed;
    all_passed = ExpectTrue(proof.message.random_commitment > 0, "ProofMessage carries random commitment") && all_passed;
    all_passed = ExpectTrue(proof.message.challenges.size() == enc.input_ciphertexts.size(), "ProofMessage carries batch challenges") && all_passed;
    all_passed = ExpectTrue(proof.message.plaintext_randomness_responses.size() == CamenischShoupEnc::PlaintextValuesPerCiphertext, "ProofMessage carries plaintext response vector") && all_passed;
    all_passed = ExpectTrue(proof.message.commitment_randomness_response > 0, "ProofMessage carries commitment randomness response") && all_passed;
    all_passed = ExpectTrue(proof.message.encryption_randomness_response > 0, "ProofMessage carries encryption randomness response") && all_passed;

    all_passed = ExpectTrue(
        zkp.VerifyEncProof(public_key, commitment_key, proof.message),
        "VerifyEncProof accepts proof message generated from Enc inputs") && all_passed;
    all_passed = ExpectTrue(
        zkp.VerifyEncProof(public_key, commitment_key, enc.input_ciphertexts, enc.input_commitments, proof.message),
        "VerifyEncProof accepts proof message with external Enc inputs") && all_passed;

    CamenischShoupEncZKP::ProofMessage tampered_message = proof.message;
    tampered_message.plaintext_randomness_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects tampered plaintext response") && all_passed;

    const NTL::ZZ beta_q(101);
    const std::vector<NTL::ZZ> beta_a = {
        NTL::ZZ(2), NTL::ZZ(3), NTL::ZZ(5), NTL::ZZ(7),
        NTL::ZZ(11), NTL::ZZ(13), NTL::ZZ(17), NTL::ZZ(19)};
    const std::vector<NTL::ZZ> beta_alpha = {
        NTL::ZZ(11), NTL::ZZ(13), NTL::ZZ(17), NTL::ZZ(19),
        NTL::ZZ(23), NTL::ZZ(29), NTL::ZZ(31), NTL::ZZ(37)};
    const std::vector<NTL::ZZ> beta_b = {
        NTL::ZZ(41), NTL::ZZ(43), NTL::ZZ(47), NTL::ZZ(53),
        NTL::ZZ(59), NTL::ZZ(61), NTL::ZZ(67), NTL::ZZ(71)};
    const std::vector<NTL::ZZ> a_commitment_randomness = {
        NTL::ZZ(73), NTL::ZZ(79)};
    const std::vector<NTL::ZZ> alpha_commitment_randomness = {
        NTL::ZZ(83), NTL::ZZ(89)};
    const std::vector<NTL::ZZ> b_commitment_randomness = {
        NTL::ZZ(97), NTL::ZZ(103)};
    const std::vector<NTL::ZZ> beta_encryption_randomness = {
        NTL::ZZ(41), NTL::ZZ(43)};
    CamenischShoupEnc::Ciphertext k2_ciphertext;
    NTL::ZZ k2_encryption_randomness;
    enc.Encrypt(
        public_key,
        std::vector<NTL::ZZ>{NTL::ZZ(107)},
        k2_encryption_randomness,
        k2_ciphertext);

    CamenischShoupEncZKP::BatchBetaProof beta_proof;
    zkp.CreateBatchBetaCiphertextsAndProof(
        public_key,
        commitment_key,
        k2_ciphertext,
        beta_q,
        beta_a,
        beta_alpha,
        beta_b,
        a_commitment_randomness,
        alpha_commitment_randomness,
        b_commitment_randomness,
        beta_encryption_randomness,
        beta_proof);

    all_passed = ExpectTrue(
        beta_proof.message.beta_ciphertexts.size() == 2,
        "BatchBeta constructs the beta ciphertext set") && all_passed;
    all_passed = ExpectTrue(
        zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            beta_proof.message),
        "BatchBeta Sigma proof verifies without decrypting base ciphertexts") && all_passed;

    CamenischShoupEncZKP::BatchBetaProofMessage tampered_beta_message = beta_proof.message;
    tampered_beta_message.beta_ciphertexts[0].u = MulMod(
        tampered_beta_message.beta_ciphertexts[0].u,
        public_key.g,
        public_key.N_zeta_plus_one);
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a tampered beta ciphertext") && all_passed;

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.alpha_commitments[1] = MulMod(
        tampered_beta_message.alpha_commitments[1],
        commitment_key.h,
        public_key.N * public_key.N);
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a tampered alpha commitment") && all_passed;

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.a_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a coefficient response not bound to the commitments") && all_passed;

    if (!all_passed)
    {
        std::cerr << "Camenisch-Shoup encryption ZKP full flow test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Camenisch-Shoup encryption ZKP full flow test passed" << std::endl;
    return EXIT_SUCCESS;
}
