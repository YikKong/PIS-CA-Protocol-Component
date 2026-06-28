#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <NTL/ZZ.h>

#include "../CamenischShoup/CamenischShoupEnc.h"
#include "../CamenischShoup/CamenischShoupEncZKP.h"
#include "../ElGamal/ElGamalEnc.h"

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

bool ExpectEqual(
    const std::vector<CamenischShoupEnc::Commitment>& actual,
    const std::vector<CamenischShoupEnc::Commitment>& expected,
    const std::string& case_name)
{
    return ExpectTrue(actual == expected, case_name);
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

    std::vector<CamenischShoupEnc::Commitment> zkp_commitments;
    zkp.GenerateCommitments(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_commitment_randomness,
        zkp_commitments);
    all_passed = ExpectEqual(zkp_commitments, enc.input_commitments, "ZKP recomputes Enc input commitments") && all_passed;

    std::vector<CamenischShoupEnc::Commitment> invalid_commitments = enc.input_commitments;
    std::vector<NTL::ZZ> oversized_plaintexts(
        enc.input_commitment_randomness.size() *
            CamenischShoupEnc::PlaintextValuesPerCiphertext +
        1,
        NTL::ZZ(1));
    zkp.GenerateCommitments(
        public_key,
        commitment_key,
        oversized_plaintexts,
        enc.input_commitment_randomness,
        invalid_commitments);
    all_passed = ExpectTrue(
        invalid_commitments.empty(),
        "GenerateCommitments rejects an oversized plaintext set") &&
        all_passed;

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
    all_passed = ExpectTrue(proof.message.random_commitment.value > 0, "ProofMessage carries random commitment") && all_passed;
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

    CamenischShoupEncZKP::ProofMessage direct_message;
    zkp.CreateEncProofMessage(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_ciphertexts,
        enc.input_encryption_randomness,
        enc.input_commitment_randomness,
        enc.input_commitments,
        direct_message);
    all_passed = ExpectTrue(
        zkp.VerifyEncProof(
            public_key,
            commitment_key,
            direct_message),
        "CreateEncProofMessage produces a verifiable proof message") &&
        all_passed;

    std::vector<NTL::ZZ> generated_commitment_randomness;
    std::vector<CamenischShoupEnc::Commitment> generated_commitments;
    CamenischShoupEncZKP::Proof generated_proof;
    zkp.GenerateCommitmentsAndEncProof(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_ciphertexts,
        enc.input_encryption_randomness,
        generated_commitment_randomness,
        generated_commitments,
        generated_proof);
    all_passed = ExpectTrue(
        generated_commitment_randomness.size() ==
            enc.input_ciphertexts.size() &&
            generated_commitments.size() ==
                enc.input_ciphertexts.size() &&
            zkp.VerifyEncProof(
                public_key,
                commitment_key,
                generated_proof.message),
        "GenerateCommitmentsAndEncProof produces commitments and a verifiable proof") &&
        all_passed;

    CamenischShoupEncZKP::Proof invalid_enc_proof;
    std::vector<NTL::ZZ> short_encryption_randomness =
        enc.input_encryption_randomness;
    short_encryption_randomness.pop_back();
    zkp.CreateEncProof(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_ciphertexts,
        short_encryption_randomness,
        enc.input_commitment_randomness,
        enc.input_commitments,
        invalid_enc_proof);
    all_passed = ExpectTrue(
        invalid_enc_proof.message.challenges.empty(),
        "CreateEncProof rejects mismatched encryption randomness") &&
        all_passed;

    CamenischShoupEncZKP::ProofMessage invalid_direct_message;
    zkp.CreateEncProofMessage(
        public_key,
        commitment_key,
        enc.input_plaintexts,
        enc.input_ciphertexts,
        short_encryption_randomness,
        enc.input_commitment_randomness,
        enc.input_commitments,
        invalid_direct_message);
    all_passed = ExpectTrue(
        invalid_direct_message.challenges.empty(),
        "CreateEncProofMessage rejects mismatched encryption randomness") &&
        all_passed;

    CamenischShoupEncZKP::ProofMessage tampered_message = proof.message;
    tampered_message.plaintext_randomness_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects tampered plaintext response") && all_passed;

    tampered_message = proof.message;
    tampered_message.challenges[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects a tampered Fiat-Shamir challenge") &&
        all_passed;

    tampered_message = proof.message;
    tampered_message.commitment_randomness_response += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects tampered commitment randomness response") &&
        all_passed;

    tampered_message = proof.message;
    tampered_message.encryption_randomness_response += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects tampered encryption randomness response") &&
        all_passed;

    tampered_message = proof.message;
    tampered_message.random_commitment.value = MulMod(
        tampered_message.random_commitment.value,
        commitment_key.h,
        public_key.N * public_key.N);
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects a tampered random commitment") &&
        all_passed;

    tampered_message = proof.message;
    tampered_message.random_ciphertext.u = MulMod(
        tampered_message.random_ciphertext.u,
        public_key.g,
        public_key.N_zeta_plus_one);
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects a tampered random ciphertext") &&
        all_passed;

    tampered_message = proof.message;
    tampered_message.challenges.pop_back();
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(public_key, commitment_key, tampered_message),
        "VerifyEncProof rejects an invalid challenge vector size") &&
        all_passed;

    std::vector<CamenischShoupEnc::Ciphertext> external_ciphertexts =
        enc.input_ciphertexts;
    external_ciphertexts[0].u = MulMod(
        external_ciphertexts[0].u,
        public_key.g,
        public_key.N_zeta_plus_one);
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(
            public_key,
            commitment_key,
            external_ciphertexts,
            enc.input_commitments,
            proof.message),
        "External VerifyEncProof binds the supplied ciphertext set") &&
        all_passed;

    const NTL::ZZ repeated_k(123);
    CamenischShoupEnc::Ciphertext repeated_k_ciphertext;
    NTL::ZZ repeated_k_encryption_randomness;
    enc.Encrypt(
        public_key,
        std::vector<NTL::ZZ>{repeated_k},
        repeated_k_encryption_randomness,
        repeated_k_ciphertext);

    std::vector<NTL::ZZ> repeated_k_commitment_plaintext(
        CamenischShoupEnc::PlaintextValuesPerCiphertext,
        repeated_k);
    CamenischShoupEnc::Commitment repeated_k_commitment;
    NTL::ZZ repeated_k_commitment_randomness;
    enc.GenerateCommitment(
        public_key,
        commitment_key,
        repeated_k_commitment_plaintext,
        repeated_k_commitment_randomness,
        repeated_k_commitment);

    CamenischShoupEncZKP::Proof repeated_commitment_proof;
    zkp.CreateEncProofWithRepeatedCommitment(
        public_key,
        commitment_key,
        repeated_k,
        repeated_k_ciphertext,
        repeated_k_encryption_randomness,
        repeated_k_commitment_randomness,
        repeated_k_commitment,
        repeated_commitment_proof);

    all_passed = ExpectTrue(
        repeated_commitment_proof.plaintexts ==
                std::vector<NTL::ZZ>{repeated_k} &&
            repeated_commitment_proof.message.challenges.size() == 1 &&
            repeated_commitment_proof.message.plaintext_randomness_responses.size() == 1 &&
            repeated_commitment_proof.message.random_ciphertext.e.size() ==
                CamenischShoupEnc::CiphertextEComponentCount &&
            repeated_commitment_proof.message.random_commitment.value > 0,
        "Repeated-commitment proof stores one scalar response for k") &&
        all_passed;
    all_passed = ExpectTrue(
        zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            repeated_commitment_proof.message),
        "Repeated-commitment proof verifies Enc([k]) against Com([k,...,k])") &&
        all_passed;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProof(
            public_key,
            commitment_key,
            repeated_commitment_proof.message),
        "Generic Enc proof rejects repeated-commitment proof shape") &&
        all_passed;

    CamenischShoupEnc::Commitment scalar_k_commitment;
    NTL::ZZ scalar_k_commitment_randomness;
    enc.GenerateCommitment(
        public_key,
        commitment_key,
        std::vector<NTL::ZZ>{repeated_k},
        scalar_k_commitment_randomness,
        scalar_k_commitment);
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            scalar_k_commitment,
            repeated_commitment_proof.message),
        "Repeated-commitment proof rejects a scalar-slot commitment") &&
        all_passed;

    CamenischShoupEnc::Ciphertext wrong_repeated_k_ciphertext;
    NTL::ZZ wrong_repeated_k_encryption_randomness;
    enc.Encrypt(
        public_key,
        std::vector<NTL::ZZ>{repeated_k + 1},
        wrong_repeated_k_encryption_randomness,
        wrong_repeated_k_ciphertext);
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            wrong_repeated_k_ciphertext,
            repeated_k_commitment,
            repeated_commitment_proof.message),
        "Repeated-commitment proof binds the supplied ciphertext") &&
        all_passed;

    CamenischShoupEncZKP::ProofMessage tampered_repeated_message =
        repeated_commitment_proof.message;
    tampered_repeated_message.plaintext_randomness_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            tampered_repeated_message),
        "Repeated-commitment proof rejects tampered plaintext response") &&
        all_passed;

    tampered_repeated_message = repeated_commitment_proof.message;
    tampered_repeated_message.commitment_randomness_response += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            tampered_repeated_message),
        "Repeated-commitment proof rejects tampered commitment randomness response") &&
        all_passed;

    tampered_repeated_message = repeated_commitment_proof.message;
    tampered_repeated_message.encryption_randomness_response += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            tampered_repeated_message),
        "Repeated-commitment proof rejects tampered encryption randomness response") &&
        all_passed;

    tampered_repeated_message = repeated_commitment_proof.message;
    tampered_repeated_message.challenges[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            tampered_repeated_message),
        "Repeated-commitment proof rejects a tampered Fiat-Shamir challenge") &&
        all_passed;

    tampered_repeated_message = repeated_commitment_proof.message;
    tampered_repeated_message.random_commitment.value = MulMod(
        tampered_repeated_message.random_commitment.value,
        commitment_key.h,
        public_key.N * public_key.N);
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            tampered_repeated_message),
        "Repeated-commitment proof rejects a tampered random commitment") &&
        all_passed;

    tampered_repeated_message = repeated_commitment_proof.message;
    tampered_repeated_message.random_ciphertext.u = MulMod(
        tampered_repeated_message.random_ciphertext.u,
        public_key.g,
        public_key.N_zeta_plus_one);
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            tampered_repeated_message),
        "Repeated-commitment proof rejects a tampered random ciphertext") &&
        all_passed;

    tampered_repeated_message = repeated_commitment_proof.message;
    tampered_repeated_message.plaintext_randomness_responses.emplace_back(NTL::ZZ(1));
    all_passed = ExpectTrue(
        !zkp.VerifyEncProofWithRepeatedCommitment(
            public_key,
            commitment_key,
            repeated_k_ciphertext,
            repeated_k_commitment,
            tampered_repeated_message),
        "Repeated-commitment proof rejects an invalid response vector size") &&
        all_passed;

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

    ElGamalEnc elgamal;
    ElGamalEnc::PublicKey elgamal_public_key;
    ElGamalEnc::SecretKey elgamal_secret_key;
    ElGamalEnc::CommitmentKey elgamal_commitment_key;
    elgamal.GenerateKeys(
        elgamal_public_key,
        elgamal_secret_key,
        elgamal_commitment_key);

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
    tampered_beta_message.alpha_commitments[1].value = MulMod(
        tampered_beta_message.alpha_commitments[1].value,
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

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.challenges[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a tampered challenge") && all_passed;

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.alpha_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a tampered alpha response") && all_passed;

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.b_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a tampered b response") && all_passed;

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.encryption_randomness_response += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a tampered encryption randomness response") &&
        all_passed;

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.random_beta_ciphertext.u = MulMod(
        tampered_beta_message.random_beta_ciphertext.u,
        public_key.g,
        public_key.N_zeta_plus_one);
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects a tampered random beta ciphertext") &&
        all_passed;

    tampered_beta_message = beta_proof.message;
    tampered_beta_message.a_responses.pop_back();
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            tampered_beta_message),
        "BatchBeta rejects an invalid slot response count") &&
        all_passed;

    CamenischShoupEncZKP::BatchBetaProof invalid_beta_proof;
    std::vector<NTL::ZZ> short_beta_a = beta_a;
    short_beta_a.pop_back();
    zkp.CreateBatchBetaCiphertextsAndProof(
        public_key,
        commitment_key,
        k2_ciphertext,
        beta_q,
        short_beta_a,
        beta_alpha,
        beta_b,
        a_commitment_randomness,
        alpha_commitment_randomness,
        b_commitment_randomness,
        beta_encryption_randomness,
        invalid_beta_proof);
    all_passed = ExpectTrue(
        invalid_beta_proof.message.beta_ciphertexts.empty(),
        "CreateBatchBetaCiphertextsAndProof rejects mismatched slot inputs") &&
        all_passed;

    CamenischShoupEncZKP::BatchBetaProof beta_proof_with_g;
    zkp.CreateBatchBetaCiphertextsAndProof(
        public_key,
        commitment_key,
        elgamal,
        elgamal_public_key,
        k2_ciphertext,
        beta_q,
        beta_a,
        beta_alpha,
        beta_b,
        a_commitment_randomness,
        alpha_commitment_randomness,
        b_commitment_randomness,
        beta_encryption_randomness,
        beta_proof_with_g);
    all_passed = ExpectTrue(
        beta_proof_with_g.message.g_to_a_values.size() ==
            beta_a.size() &&
            beta_proof_with_g.message.random_g_to_a_values.size() ==
                CamenischShoupEnc::PlaintextValuesPerCiphertext,
        "BatchBeta with ElGamal carries one g^a value per slot") &&
        all_passed;
    all_passed = ExpectTrue(
        zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_public_key,
            beta_proof_with_g.message),
        "BatchBeta with ElGamal verifies g^a values against the same a witness") &&
        all_passed;

    tampered_beta_message = beta_proof_with_g.message;
    tampered_beta_message.g_to_a_values[0] =
        beta_proof_with_g.message.g_to_a_values[1];
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_public_key,
            tampered_beta_message),
        "BatchBeta with ElGamal rejects a tampered g^a value") &&
        all_passed;

    tampered_beta_message = beta_proof_with_g.message;
    tampered_beta_message.g_to_a_values.pop_back();
    all_passed = ExpectTrue(
        !zkp.VerifyBatchBetaProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_public_key,
            tampered_beta_message),
        "BatchBeta with ElGamal rejects a missing g^a value") &&
        all_passed;

    CamenischShoupEncZKP::DecProof dec_proof;
    zkp.CreateDecProofAndCommitments(
        public_key,
        secret_key,
        commitment_key,
        elgamal,
        elgamal_commitment_key,
        enc.input_ciphertexts,
        dec_proof);

    all_passed = ExpectEqual(
        dec_proof.beta,
        enc.input_plaintexts,
        "Dec proof stores the decrypted beta set") && all_passed;
    all_passed = ExpectTrue(
        dec_proof.message.camenisch_shoup_beta_commitments.size() ==
            enc.input_ciphertexts.size(),
        "Dec proof generates one Camenisch-Shoup vector commitment per ciphertext") &&
        all_passed;
    all_passed = ExpectTrue(
        dec_proof.message.elgamal_beta_commitments.size() ==
            enc.input_plaintexts.size(),
        "Dec proof generates one ElGamal scalar commitment per beta") &&
        all_passed;
    all_passed = ExpectTrue(
        !dec_proof.elgamal_commitment_randomness.empty() &&
            dec_proof.elgamal_commitment_randomness[0] != nullptr &&
            !BN_is_zero(
                dec_proof.elgamal_commitment_randomness[0].get()) &&
            BN_cmp(
                dec_proof.elgamal_commitment_randomness[0].get(),
                elgamal.Order()) < 0,
        "ElGamal commitment randomness is a random BIGNUM scalar") &&
        all_passed;
    all_passed = ExpectTrue(
        zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            dec_proof.message),
        "Dec proof verifies beta decryption and both commitment families") &&
        all_passed;

    CamenischShoupEncZKP::DecProofMessage tampered_dec_message =
        dec_proof.message;
    tampered_dec_message.beta_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a tampered beta response") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.camenisch_shoup_beta_commitments[0].value =
        MulMod(
        tampered_dec_message.camenisch_shoup_beta_commitments[0].value,
        commitment_key.h,
        public_key.N * public_key.N);
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a tampered Camenisch-Shoup beta commitment") &&
        all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.elgamal_beta_commitments[0] =
        dec_proof.message.elgamal_beta_commitments[1];
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a tampered ElGamal beta commitment") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.batch_challenges[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a tampered batch challenge") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.final_challenge += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a tampered final challenge") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.secret_key_responses[0] += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a tampered secret-key response") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.decryption_announcements[0] = 0;
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects an invalid decryption announcement") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.random_ciphertext.u = MulMod(
        tampered_dec_message.random_ciphertext.u,
        public_key.g,
        public_key.N_zeta_plus_one);
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a tampered random ciphertext") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.camenisch_shoup_commitment_randomness_response += 1;
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects tampered Camenisch-Shoup commitment randomness") &&
        all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.beta_responses.pop_back();
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects an invalid beta response count") && all_passed;

    tampered_dec_message = dec_proof.message;
    tampered_dec_message.elgamal_commitment_randomness_responses[0].reset();
    all_passed = ExpectTrue(
        !zkp.VerifyDecProof(
            public_key,
            commitment_key,
            elgamal,
            elgamal_commitment_key,
            tampered_dec_message),
        "Dec proof rejects a null ElGamal randomness response") && all_passed;

    CamenischShoupEncZKP::DecProof invalid_dec_proof;
    zkp.CreateDecProofAndCommitments(
        public_key,
        secret_key,
        commitment_key,
        elgamal,
        elgamal_commitment_key,
        std::vector<CamenischShoupEnc::Ciphertext>{},
        invalid_dec_proof);
    all_passed = ExpectTrue(
        invalid_dec_proof.message.ciphertexts.empty() &&
            invalid_dec_proof.beta.empty(),
        "CreateDecProofAndCommitments rejects an empty ciphertext set") &&
        all_passed;

    if (!all_passed)
    {
        std::cerr << "Camenisch-Shoup encryption ZKP full flow test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Camenisch-Shoup encryption ZKP full flow test passed" << std::endl;
    return EXIT_SUCCESS;
}
