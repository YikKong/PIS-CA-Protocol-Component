#include "CamenischShoupEncZKP.h"

#include <array>
#include <iostream>
#include <sstream>
#include <string>

#include <openssl/sha.h>

namespace
{
    NTL::ZZ HashToZZ(const std::string& input)
    {
        std::array<std::uint8_t, CamenischShoupEnc::HashBytes> digest{};
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, input.data(), input.size());
        SHA256_Final(digest.data(), &ctx);

        NTL::ZZ challenge(0);
        for (std::uint8_t byte : digest)
        {
            challenge *= 256;
            challenge += byte;
        }

        return challenge;
    }

    void AppendZZ(std::ostringstream& stream, const NTL::ZZ& value)
    {
        stream << value << '|';
    }

    void AppendVector(std::ostringstream& stream, const std::vector<NTL::ZZ>& values)
    {
        stream << values.size() << '|';
        for (const NTL::ZZ& value : values)
        {
            AppendZZ(stream, value);
        }
    }

    void AppendCommitment(
        std::ostringstream& stream,
        const CamenischShoupEnc::Commitment& commitment)
    {
        AppendZZ(stream, commitment.value);
    }

    void AppendCommitments(
        std::ostringstream& stream,
        const std::vector<CamenischShoupEnc::Commitment>& commitments)
    {
        stream << commitments.size() << '|';
        for (const CamenischShoupEnc::Commitment& commitment : commitments)
        {
            AppendCommitment(stream, commitment);
        }
    }

    void AppendCiphertext(std::ostringstream& stream, const CamenischShoupEnc::Ciphertext& ciphertext)
    {
        AppendZZ(stream, ciphertext.u);
        AppendVector(stream, ciphertext.e);
    }

    void AppendCiphertexts(std::ostringstream& stream, const std::vector<CamenischShoupEnc::Ciphertext>& ciphertexts)
    {
        stream << ciphertexts.size() << '|';
        for (const CamenischShoupEnc::Ciphertext& ciphertext : ciphertexts)
        {
            AppendCiphertext(stream, ciphertext);
        }
    }
}

CamenischShoupEncZKP::CamenischShoupEncZKP(const CamenischShoupEnc& encryption)
    : encryption_(encryption)
{
}

void CamenischShoupEncZKP::GenerateCommitments(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& plaintexts,
    const std::vector<NTL::ZZ>& commitment_randomness,
    std::vector<Commitment>& commitments) const
{
    commitments.clear();
    commitments.reserve(commitment_randomness.size());

    if (plaintexts.size() > commitment_randomness.size() * CamenischShoupEnc::PlaintextValuesPerCiphertext)
    {
        std::cout << "commitment plaintext size error " << std::endl;
        return;
    }

    for (std::uint32_t batch_index = 0; batch_index < commitment_randomness.size(); ++batch_index)
    {
        commitments.emplace_back(GenerateCommitment(
            public_key,
            commitment_key,
            plaintexts,
            commitment_randomness[batch_index],
            batch_index));
    }
}

void CamenischShoupEncZKP::CreateEncProof(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& plaintexts,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<NTL::ZZ>& encryption_randomness,
    const std::vector<NTL::ZZ>& commitment_randomness,
    const std::vector<Commitment>& commitments,
    Proof& proof) const
{
    proof.plaintexts = plaintexts;
    proof.ciphertexts = ciphertexts;
    proof.encryption_randomness = encryption_randomness;
    proof.commitment_randomness = commitment_randomness;
    proof.commitments = commitments;

    const std::uint32_t batch_size = static_cast<std::uint32_t>(ciphertexts.size());
    if (!HasExpectedSizes(public_key, commitment_key, ciphertexts, commitments) ||
        encryption_randomness.size() != batch_size ||
        commitment_randomness.size() != batch_size ||
        plaintexts.size() > batch_size * CamenischShoupEnc::PlaintextValuesPerCiphertext)
    {
        std::cout << "proof input size error " << std::endl;
        return;
    }

    proof.plaintext_randomness.clear();
    proof.plaintext_randomness.reserve(CamenischShoupEnc::PlaintextValuesPerCiphertext);
    for (std::uint32_t i = 0; i < CamenischShoupEnc::PlaintextValuesPerCiphertext; ++i)
    {
        NTL::ZZ plaintext_mask;
        RandomBits(plaintext_mask, CamenischShoupEnc::SubPlaintextLens - 10);
        proof.plaintext_randomness.emplace_back(plaintext_mask);
    }

    RandomBits(proof.encryption_randomness_mask, NumBits(public_key.N) - 10);
    RandomBits(proof.commitment_randomness_mask, NumBits(public_key.N) - 10);

    proof.message.ciphertexts = proof.ciphertexts;
    proof.message.commitments = proof.commitments;
    encryption_.EncryptWithRandomness(
        public_key,
        proof.plaintext_randomness,
        proof.encryption_randomness_mask,
        proof.message.random_ciphertext);
    proof.message.random_commitment = GenerateCommitment(
        public_key,
        commitment_key,
        proof.plaintext_randomness,
        proof.commitment_randomness_mask,
        0);

    GenerateChallenges(
        public_key,
        proof.message.ciphertexts,
        proof.message.commitments,
        proof.message.random_ciphertext,
        proof.message.random_commitment,
        proof.message.challenges);

    proof.message.plaintext_randomness_responses.clear();
    proof.message.plaintext_randomness_responses.reserve(CamenischShoupEnc::PlaintextValuesPerCiphertext);
    for (std::uint32_t slot_index = 0; slot_index < CamenischShoupEnc::PlaintextValuesPerCiphertext; ++slot_index)
    {
        NTL::ZZ response = proof.plaintext_randomness[slot_index];
        for (std::uint32_t batch_index = 0; batch_index < batch_size; ++batch_index)
        {
            const std::uint32_t plaintext_index = batch_index * CamenischShoupEnc::PlaintextValuesPerCiphertext + slot_index;
            const NTL::ZZ plaintext_value = plaintext_index < proof.plaintexts.size() ? proof.plaintexts[plaintext_index] : NTL::ZZ(0);
            response += proof.message.challenges[batch_index] * plaintext_value;
        }
        proof.message.plaintext_randomness_responses.emplace_back(response);
    }

    proof.message.commitment_randomness_response = proof.commitment_randomness_mask;
    proof.message.encryption_randomness_response = proof.encryption_randomness_mask;
    for (std::uint32_t batch_index = 0; batch_index < batch_size; ++batch_index)
    {
        proof.message.commitment_randomness_response += proof.message.challenges[batch_index] * proof.commitment_randomness[batch_index];
        proof.message.encryption_randomness_response += proof.message.challenges[batch_index] * proof.encryption_randomness[batch_index];
    }
}

void CamenischShoupEncZKP::CreateEncProofMessage(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& plaintexts,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<NTL::ZZ>& encryption_randomness,
    const std::vector<NTL::ZZ>& commitment_randomness,
    const std::vector<Commitment>& commitments,
    ProofMessage& proof_message) const
{
    const std::uint32_t batch_size = static_cast<std::uint32_t>(ciphertexts.size());
    if (!HasExpectedSizes(public_key, commitment_key, ciphertexts, commitments) ||
        encryption_randomness.size() != batch_size ||
        commitment_randomness.size() != batch_size ||
        plaintexts.size() > batch_size * CamenischShoupEnc::PlaintextValuesPerCiphertext)
    {
        std::cout << "proof input size error " << std::endl;
        return;
    }

    proof_message.ciphertexts = ciphertexts;
    proof_message.commitments = commitments;

    std::vector<NTL::ZZ> plaintext_randomness;
    plaintext_randomness.reserve(CamenischShoupEnc::PlaintextValuesPerCiphertext);
    for (std::uint32_t i = 0; i < CamenischShoupEnc::PlaintextValuesPerCiphertext; ++i)
    {
        NTL::ZZ plaintext_mask;
        RandomBits(plaintext_mask, CamenischShoupEnc::SubPlaintextLens - 10);
        plaintext_randomness.emplace_back(plaintext_mask);
    }

    NTL::ZZ encryption_randomness_mask;
    RandomBits(encryption_randomness_mask, NumBits(public_key.N) - 10);
    encryption_.EncryptWithRandomness(
        public_key,
        plaintext_randomness,
        encryption_randomness_mask,
        proof_message.random_ciphertext);

    NTL::ZZ commitment_randomness_mask;
    RandomBits(commitment_randomness_mask, NumBits(public_key.N) - 10);
    proof_message.random_commitment = GenerateCommitment(
        public_key,
        commitment_key,
        plaintext_randomness,
        commitment_randomness_mask,
        0);

    GenerateChallenges(
        public_key,
        proof_message.ciphertexts,
        proof_message.commitments,
        proof_message.random_ciphertext,
        proof_message.random_commitment,
        proof_message.challenges);

    proof_message.plaintext_randomness_responses.clear();
    proof_message.plaintext_randomness_responses.reserve(CamenischShoupEnc::PlaintextValuesPerCiphertext);
    for (std::uint32_t slot_index = 0; slot_index < CamenischShoupEnc::PlaintextValuesPerCiphertext; ++slot_index)
    {
        NTL::ZZ response = plaintext_randomness[slot_index];
        for (std::uint32_t batch_index = 0; batch_index < batch_size; ++batch_index)
        {
            const std::uint32_t plaintext_index = batch_index * CamenischShoupEnc::PlaintextValuesPerCiphertext + slot_index;
            const NTL::ZZ plaintext_value = plaintext_index < plaintexts.size() ? plaintexts[plaintext_index] : NTL::ZZ(0);
            response += proof_message.challenges[batch_index] * plaintext_value;
        }
        proof_message.plaintext_randomness_responses.emplace_back(response);
    }

    proof_message.commitment_randomness_response = commitment_randomness_mask;
    proof_message.encryption_randomness_response = encryption_randomness_mask;
    for (std::uint32_t batch_index = 0; batch_index < batch_size; ++batch_index)
    {
        proof_message.commitment_randomness_response += proof_message.challenges[batch_index] * commitment_randomness[batch_index];
        proof_message.encryption_randomness_response += proof_message.challenges[batch_index] * encryption_randomness[batch_index];
    }
}

void CamenischShoupEncZKP::GenerateCommitmentsAndEncProof(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& plaintexts,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<NTL::ZZ>& encryption_randomness,
    std::vector<NTL::ZZ>& commitment_randomness,
    std::vector<Commitment>& commitments,
    Proof& proof) const
{
    const std::uint32_t batch_size = static_cast<std::uint32_t>(ciphertexts.size());
    commitment_randomness.clear();
    commitment_randomness.reserve(batch_size);
    for (std::uint32_t i = 0; i < batch_size; ++i)
    {
        NTL::ZZ randomness;
        RandomBits(randomness, NumBits(public_key.N) - 10);
        commitment_randomness.emplace_back(randomness);
    }

    GenerateCommitments(public_key, commitment_key, plaintexts, commitment_randomness, commitments);
    CreateEncProof(
        public_key,
        commitment_key,
        plaintexts,
        ciphertexts,
        encryption_randomness,
        commitment_randomness,
        commitments,
        proof);
}

bool CamenischShoupEncZKP::VerifyEncProof(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const ProofMessage& proof_message) const
{
    return VerifyEncProof(
        public_key,
        commitment_key,
        proof_message.ciphertexts,
        proof_message.commitments,
        proof_message);
}

bool CamenischShoupEncZKP::VerifyEncProof(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<Commitment>& commitments,
    const ProofMessage& proof_message) const
{
    const std::uint32_t batch_size = static_cast<std::uint32_t>(ciphertexts.size());
    if (!HasExpectedSizes(public_key, commitment_key, ciphertexts, commitments) ||
        proof_message.ciphertexts.size() != batch_size ||
        proof_message.commitments != commitments ||
        proof_message.random_ciphertext.e.size() != CamenischShoupEnc::CiphertextEComponentCount ||
        proof_message.challenges.size() != batch_size ||
        proof_message.plaintext_randomness_responses.size() != CamenischShoupEnc::PlaintextValuesPerCiphertext)
    {
        return false;
    }

    for (std::uint32_t batch_index = 0; batch_index < batch_size; ++batch_index)
    {
        if (proof_message.ciphertexts[batch_index].u != ciphertexts[batch_index].u ||
            proof_message.ciphertexts[batch_index].e != ciphertexts[batch_index].e)
        {
            return false;
        }
    }

    std::vector<NTL::ZZ> challenges;
    GenerateChallenges(
        public_key,
        ciphertexts,
        commitments,
        proof_message.random_ciphertext,
        proof_message.random_commitment,
        challenges);

    if (challenges != proof_message.challenges)
    {
        return false;
    }

    const NTL::ZZ commitment_modulus = public_key.N * public_key.N;
    const Commitment commitment_left = GenerateCommitment(
        public_key,
        commitment_key,
        proof_message.plaintext_randomness_responses,
        proof_message.commitment_randomness_response,
        0);

    NTL::ZZ commitment_right = proof_message.random_commitment.value;
    for (std::uint32_t batch_index = 0; batch_index < batch_size; ++batch_index)
    {
        const NTL::ZZ commitment_challenge = PowerMod(commitments[batch_index].value, challenges[batch_index], commitment_modulus);
        commitment_right = MulMod(commitment_right, commitment_challenge, commitment_modulus);
    }

    if (commitment_left.value != commitment_right)
    {
        return false;
    }

    Ciphertext encryption_left;
    encryption_.EncryptWithRandomness(
        public_key,
        proof_message.plaintext_randomness_responses,
        proof_message.encryption_randomness_response,
        encryption_left);

    Ciphertext encryption_right = proof_message.random_ciphertext;
    for (std::uint32_t batch_index = 0; batch_index < batch_size; ++batch_index)
    {
        Ciphertext encrypted_challenge;
        encryption_.ScalarMultiply(public_key, encrypted_challenge, ciphertexts[batch_index], challenges[batch_index]);

        Ciphertext next_encryption_right;
        encryption_.HomomorphicAdd(public_key, next_encryption_right, encryption_right, encrypted_challenge);
        encryption_right = next_encryption_right;
    }

    if (encryption_left.u != encryption_right.u || encryption_left.e.size() != encryption_right.e.size())
    {
        return false;
    }

    for (std::uint32_t i = 0; i < encryption_left.e.size(); ++i)
    {
        if (encryption_left.e[i] != encryption_right.e[i])
        {
            return false;
        }
    }

    return true;
}

CamenischShoupEncZKP::Commitment CamenischShoupEncZKP::GenerateCommitment(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& plaintexts,
    const NTL::ZZ& commitment_randomness,
    std::uint32_t batch_index) const
{
    const std::uint32_t first_slot = batch_index * CamenischShoupEnc::PlaintextValuesPerCiphertext;
    std::vector<NTL::ZZ> plaintext;
    plaintext.reserve(CamenischShoupEnc::PlaintextValuesPerCiphertext);
    for (std::uint32_t i = 0;
         i < CamenischShoupEnc::PlaintextValuesPerCiphertext &&
             first_slot + i < plaintexts.size();
         ++i)
    {
        plaintext.emplace_back(plaintexts[first_slot + i]);
    }

    Commitment commitment;
    encryption_.GenerateCommitmentWithRandomness(
        public_key,
        commitment_key,
        plaintext,
        commitment_randomness,
        commitment);
    return commitment;
}

NTL::ZZ CamenischShoupEncZKP::GenerateChallenge(
    const PublicKey& public_key,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<Commitment>& commitments,
    const Ciphertext& random_ciphertext,
    const Commitment& random_commitment,
    std::uint32_t challenge_index) const
{
    std::ostringstream stream;
    AppendZZ(stream, public_key.N);
    AppendZZ(stream, public_key.N_zeta_plus_one);
    AppendZZ(stream, public_key.T);
    AppendZZ(stream, public_key.g);
    AppendVector(stream, public_key.pk);
    AppendCiphertexts(stream, ciphertexts);
    AppendCommitments(stream, commitments);
    AppendCiphertext(stream, random_ciphertext);
    AppendCommitment(stream, random_commitment);
    stream << challenge_index << '|';

    return HashToZZ(stream.str());
}

void CamenischShoupEncZKP::GenerateChallenges(
    const PublicKey& public_key,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<Commitment>& commitments,
    const Ciphertext& random_ciphertext,
    const Commitment& random_commitment,
    std::vector<NTL::ZZ>& challenges) const
{
    challenges.clear();
    challenges.reserve(ciphertexts.size());
    for (std::uint32_t i = 0; i < ciphertexts.size(); ++i)
    {
        challenges.emplace_back(GenerateChallenge(
            public_key,
            ciphertexts,
            commitments,
            random_ciphertext,
            random_commitment,
            i));
    }
}

bool CamenischShoupEncZKP::HasExpectedSizes(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<Ciphertext>& ciphertexts,
    const std::vector<Commitment>& commitments) const
{
    if (public_key.pk.size() != CamenischShoupEnc::CiphertextEComponentCount ||
        commitment_key.g.size() < CamenischShoupEnc::CommitmentGeneratorCount ||
        ciphertexts.empty() ||
        commitments.size() != ciphertexts.size())
    {
        return false;
    }

    for (const Ciphertext& ciphertext : ciphertexts)
    {
        if (ciphertext.e.size() != CamenischShoupEnc::CiphertextEComponentCount)
        {
            return false;
        }
    }

    return true;
}

CamenischShoupEncZKP::Commitment CamenischShoupEncZKP::GenerateVectorCommitment(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& values,
    const NTL::ZZ& randomness) const
{
    Commitment commitment;
    encryption_.GenerateCommitmentWithRandomness(
        public_key,
        commitment_key,
        values,
        randomness,
        commitment);
    return commitment;
}

NTL::ZZ CamenischShoupEncZKP::PackBatchValues(
    const PublicKey& public_key,
    const std::vector<NTL::ZZ>& values) const
{
    NTL::ZZ packed(0);
    for (std::uint32_t i = 0; i < values.size(); ++i)
    {
        packed += values[i] * power(public_key.plaintext_packing_base, i);
    }
    return packed;
}

CamenischShoupEncZKP::Ciphertext CamenischShoupEncZKP::EvaluateBetaCiphertext(
    const PublicKey& public_key,
    const Ciphertext& base_ciphertext,
    const std::vector<NTL::ZZ>& a,
    const std::vector<NTL::ZZ>& alpha,
    const std::vector<NTL::ZZ>& b,
    const NTL::ZZ& q,
    const NTL::ZZ& encryption_randomness) const
{
    std::vector<NTL::ZZ> additive_plaintext;
    additive_plaintext.reserve(alpha.size());
    for (std::uint32_t i = 0; i < alpha.size(); ++i)
    {
        additive_plaintext.emplace_back(alpha[i] + q * b[i]);
    }

    Ciphertext result;
    encryption_.EncryptWithRandomness(
        public_key,
        additive_plaintext,
        encryption_randomness,
        result);

    Ciphertext scaled_base;
    Ciphertext accumulated;
    encryption_.ScalarMultiply(
        public_key,
        scaled_base,
        base_ciphertext,
        PackBatchValues(public_key, a));
    encryption_.HomomorphicAdd(public_key, accumulated, result, scaled_base);
    result = accumulated;
    return result;
}

void CamenischShoupEncZKP::CreateBatchBetaCiphertextsAndProof(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const Ciphertext& base_ciphertext,
    const NTL::ZZ& q,
    const std::vector<NTL::ZZ>& a,
    const std::vector<NTL::ZZ>& alpha,
    const std::vector<NTL::ZZ>& b,
    const std::vector<NTL::ZZ>& a_commitment_randomness,
    const std::vector<NTL::ZZ>& alpha_commitment_randomness,
    const std::vector<NTL::ZZ>& b_commitment_randomness,
    const std::vector<NTL::ZZ>& encryption_randomness,
    BatchBetaProof& proof) const
{
    static_assert(
        CamenischShoupEnc::CiphertextEComponentCount == 1,
        "BatchBeta proof assumes one ciphertext e component");

    proof = BatchBetaProof{};
    proof.a = a;
    proof.alpha = alpha;
    proof.b = b;
    proof.a_commitment_randomness = a_commitment_randomness;
    proof.alpha_commitment_randomness = alpha_commitment_randomness;
    proof.b_commitment_randomness = b_commitment_randomness;
    proof.encryption_randomness = encryption_randomness;
    BatchBetaProofMessage& proof_message = proof.message;

    const std::uint32_t output_count =
        static_cast<std::uint32_t>(encryption_randomness.size());
    const std::uint32_t slot_count = CamenischShoupEnc::PlaintextValuesPerCiphertext;
    const long value_mask_bits = CamenischShoupEnc::SubPlaintextLens - 10;
    const long b_mask_bits = value_mask_bits - NumBits(q);

    if (output_count == 0 ||
        q < 0 ||
        b_mask_bits <= 0 ||
        commitment_key.g.size() < slot_count ||
        a.size() != output_count * slot_count ||
        alpha.size() != output_count * slot_count ||
        b.size() != output_count * slot_count ||
        a_commitment_randomness.size() != output_count ||
        alpha_commitment_randomness.size() != output_count ||
        b_commitment_randomness.size() != output_count)
    {
        std::cout << "batch beta proof input size error " << std::endl;
        return;
    }

    if (!IsValidCiphertext(public_key, base_ciphertext))
    {
        std::cout << "batch beta base input error " << std::endl;
        return;
    }
    for (const NTL::ZZ& value : a)
    {
        if (value < 0 || value >= public_key.plaintext_packing_base)
        {
            std::cout << "batch beta a slot range error " << std::endl;
            return;
        }
    }
    for (std::uint32_t i = 0; i < alpha.size(); ++i)
    {
        if (alpha[i] < 0 ||
            b[i] < 0 ||
            alpha[i] + q * b[i] >= public_key.plaintext_packing_base)
        {
            std::cout << "batch beta alpha plus q times b slot range error " << std::endl;
            return;
        }
    }

    proof_message.base_ciphertext = base_ciphertext;
    proof_message.q = q;
    proof_message.a_commitments.reserve(output_count);
    proof_message.alpha_commitments.reserve(output_count);
    proof_message.b_commitments.reserve(output_count);
    proof_message.beta_ciphertexts.reserve(output_count);

    proof.a_masks.reserve(a.size());
    for (std::uint32_t s = 0; s < output_count; ++s)
    {
        const auto a_begin = a.begin() + s * slot_count;
        const std::vector<NTL::ZZ> a_slice(a_begin, a_begin + slot_count);
        const auto alpha_begin = alpha.begin() + s * slot_count;
        const std::vector<NTL::ZZ> alpha_slice(alpha_begin, alpha_begin + slot_count);
        const auto b_begin = b.begin() + s * slot_count;
        const std::vector<NTL::ZZ> b_slice(b_begin, b_begin + slot_count);

        proof_message.a_commitments.emplace_back(GenerateVectorCommitment(
            public_key,
            commitment_key,
            a_slice,
            a_commitment_randomness[s]));
        proof_message.alpha_commitments.emplace_back(GenerateVectorCommitment(
            public_key,
            commitment_key,
            alpha_slice,
            alpha_commitment_randomness[s]));
        proof_message.b_commitments.emplace_back(GenerateVectorCommitment(
            public_key,
            commitment_key,
            b_slice,
            b_commitment_randomness[s]));
        proof_message.beta_ciphertexts.emplace_back(EvaluateBetaCiphertext(
            public_key,
            base_ciphertext,
            a_slice,
            alpha_slice,
            b_slice,
            q,
            encryption_randomness[s]));
    }

    proof.a_masks.clear();
    proof.alpha_masks.clear();
    proof.b_masks.clear();
    proof.a_masks.reserve(slot_count);
    proof.alpha_masks.reserve(slot_count);
    proof.b_masks.reserve(slot_count);
    for (std::uint32_t i = 0; i < slot_count; ++i)
    {
        NTL::ZZ a_mask;
        NTL::ZZ alpha_mask;
        NTL::ZZ b_mask;
        RandomBits(a_mask, value_mask_bits);
        RandomBits(alpha_mask, value_mask_bits);
        RandomBits(b_mask, b_mask_bits);
        proof.a_masks.emplace_back(a_mask);
        proof.alpha_masks.emplace_back(alpha_mask);
        proof.b_masks.emplace_back(b_mask);
    }

    RandomBits(proof.a_commitment_randomness_mask, 2 * CamenischShoupEnc::PrimeBits);
    RandomBits(proof.alpha_commitment_randomness_mask, 2 * CamenischShoupEnc::PrimeBits);
    RandomBits(proof.b_commitment_randomness_mask, 2 * CamenischShoupEnc::PrimeBits);
    RandomBits(proof.encryption_randomness_mask, 2 * CamenischShoupEnc::PrimeBits);

    proof_message.random_a_commitment = GenerateVectorCommitment(
        public_key,
        commitment_key,
        proof.a_masks,
        proof.a_commitment_randomness_mask);
    proof_message.random_alpha_commitment = GenerateVectorCommitment(
        public_key,
        commitment_key,
        proof.alpha_masks,
        proof.alpha_commitment_randomness_mask);
    proof_message.random_b_commitment = GenerateVectorCommitment(
        public_key,
        commitment_key,
        proof.b_masks,
        proof.b_commitment_randomness_mask);
    proof_message.random_beta_ciphertext = EvaluateBetaCiphertext(
        public_key,
        base_ciphertext,
        proof.a_masks,
        proof.alpha_masks,
        proof.b_masks,
        q,
        proof.encryption_randomness_mask);

    proof_message.challenges.reserve(output_count);
    for (std::uint32_t s = 0; s < output_count; ++s)
    {
        proof_message.challenges.emplace_back(GenerateBatchBetaChallenge(
            public_key,
            commitment_key,
            proof_message,
            s));
    }

    proof_message.a_responses = proof.a_masks;
    proof_message.alpha_responses = proof.alpha_masks;
    proof_message.b_responses = proof.b_masks;
    proof_message.a_commitment_randomness_response =
        proof.a_commitment_randomness_mask;
    proof_message.alpha_commitment_randomness_response =
        proof.alpha_commitment_randomness_mask;
    proof_message.b_commitment_randomness_response =
        proof.b_commitment_randomness_mask;
    proof_message.encryption_randomness_response =
        proof.encryption_randomness_mask;

    for (std::uint32_t s = 0; s < output_count; ++s)
    {
        const NTL::ZZ& challenge = proof_message.challenges[s];
        for (std::uint32_t i = 0; i < slot_count; ++i)
        {
            const std::uint32_t index = s * slot_count + i;
            proof_message.a_responses[i] += challenge * a[index];
            proof_message.alpha_responses[i] += challenge * alpha[index];
            proof_message.b_responses[i] += challenge * b[index];
        }
        proof_message.a_commitment_randomness_response +=
            challenge * a_commitment_randomness[s];
        proof_message.alpha_commitment_randomness_response +=
            challenge * alpha_commitment_randomness[s];
        proof_message.b_commitment_randomness_response +=
            challenge * b_commitment_randomness[s];
        proof_message.encryption_randomness_response +=
            challenge * encryption_randomness[s];
    }
}

bool CamenischShoupEncZKP::VerifyBatchBetaProof(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const BatchBetaProofMessage& proof_message) const
{
    static_assert(
        CamenischShoupEnc::CiphertextEComponentCount == 1,
        "BatchBeta proof assumes one ciphertext e component");

    const std::uint32_t output_count =
        static_cast<std::uint32_t>(proof_message.beta_ciphertexts.size());
    const std::uint32_t slot_count = CamenischShoupEnc::PlaintextValuesPerCiphertext;

    if (output_count == 0 ||
        proof_message.q < 0 ||
        commitment_key.g.size() < slot_count ||
        proof_message.a_commitments.size() != output_count ||
        proof_message.alpha_commitments.size() != output_count ||
        proof_message.b_commitments.size() != output_count ||
        proof_message.challenges.size() != output_count ||
        proof_message.a_responses.size() != slot_count ||
        proof_message.alpha_responses.size() != slot_count ||
        proof_message.b_responses.size() != slot_count)
    {
        return false;
    }

    if (!IsValidCiphertext(public_key, proof_message.base_ciphertext) ||
        !IsValidCiphertext(public_key, proof_message.random_beta_ciphertext) ||
        !IsValidCommitment(public_key, proof_message.random_a_commitment) ||
        !IsValidCommitment(public_key, proof_message.random_alpha_commitment) ||
        !IsValidCommitment(public_key, proof_message.random_b_commitment))
    {
        return false;
    }

    const NTL::ZZ commitment_modulus = public_key.N * public_key.N;
    NTL::ZZ a_right = proof_message.random_a_commitment.value;
    NTL::ZZ alpha_right = proof_message.random_alpha_commitment.value;
    NTL::ZZ b_right = proof_message.random_b_commitment.value;
    Ciphertext beta_right = proof_message.random_beta_ciphertext;

    for (std::uint32_t s = 0; s < output_count; ++s)
    {
        if (!IsValidCiphertext(public_key, proof_message.beta_ciphertexts[s]) ||
            !IsValidCommitment(public_key, proof_message.a_commitments[s]) ||
            !IsValidCommitment(public_key, proof_message.alpha_commitments[s]) ||
            !IsValidCommitment(public_key, proof_message.b_commitments[s]))
        {
            return false;
        }

        const NTL::ZZ expected_challenge = GenerateBatchBetaChallenge(
            public_key,
            commitment_key,
            proof_message,
            s);
        if (proof_message.challenges[s] != expected_challenge)
        {
            return false;
        }

        a_right = MulMod(
            a_right,
            PowerMod(
                proof_message.a_commitments[s].value,
                expected_challenge,
                commitment_modulus),
            commitment_modulus);
        alpha_right = MulMod(
            alpha_right,
            PowerMod(
                proof_message.alpha_commitments[s].value,
                expected_challenge,
                commitment_modulus),
            commitment_modulus);
        b_right = MulMod(
            b_right,
            PowerMod(
                proof_message.b_commitments[s].value,
                expected_challenge,
                commitment_modulus),
            commitment_modulus);

        Ciphertext challenged_beta;
        Ciphertext accumulated_beta;
        encryption_.ScalarMultiply(
            public_key,
            challenged_beta,
            proof_message.beta_ciphertexts[s],
            expected_challenge);
        encryption_.HomomorphicAdd(
            public_key,
            accumulated_beta,
            beta_right,
            challenged_beta);
        beta_right = accumulated_beta;
    }

    const Commitment a_left = GenerateVectorCommitment(
        public_key,
        commitment_key,
        proof_message.a_responses,
        proof_message.a_commitment_randomness_response);
    const Commitment alpha_left = GenerateVectorCommitment(
        public_key,
        commitment_key,
        proof_message.alpha_responses,
        proof_message.alpha_commitment_randomness_response);
    const Commitment b_left = GenerateVectorCommitment(
        public_key,
        commitment_key,
        proof_message.b_responses,
        proof_message.b_commitment_randomness_response);
    if (a_left.value != a_right ||
        alpha_left.value != alpha_right ||
        b_left.value != b_right)
    {
        return false;
    }

    const Ciphertext beta_left = EvaluateBetaCiphertext(
        public_key,
        proof_message.base_ciphertext,
        proof_message.a_responses,
        proof_message.alpha_responses,
        proof_message.b_responses,
        proof_message.q,
        proof_message.encryption_randomness_response);
    if (beta_left.u != beta_right.u || beta_left.e != beta_right.e)
    {
        return false;
    }

    return true;
}

NTL::ZZ CamenischShoupEncZKP::GenerateBatchBetaChallenge(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const BatchBetaProofMessage& proof_message,
    std::uint32_t output_index) const
{
    std::ostringstream stream;
    stream << "CamenischShoupBatchBetaSigmaProof|";
    AppendZZ(stream, public_key.N);
    AppendZZ(stream, public_key.N_zeta_plus_one);
    AppendZZ(stream, public_key.T);
    AppendZZ(stream, public_key.g);
    AppendVector(stream, public_key.pk);
    AppendVector(stream, commitment_key.g);
    AppendZZ(stream, commitment_key.h);
    AppendCiphertext(stream, proof_message.base_ciphertext);
    AppendZZ(stream, proof_message.q);
    AppendCommitments(stream, proof_message.a_commitments);
    AppendCommitments(stream, proof_message.alpha_commitments);
    AppendCommitments(stream, proof_message.b_commitments);
    AppendCiphertexts(stream, proof_message.beta_ciphertexts);
    AppendCommitment(stream, proof_message.random_a_commitment);
    AppendCommitment(stream, proof_message.random_alpha_commitment);
    AppendCommitment(stream, proof_message.random_b_commitment);
    AppendCiphertext(stream, proof_message.random_beta_ciphertext);
    stream << output_index << '|';
    return HashToZZ(stream.str());
}

bool CamenischShoupEncZKP::IsValidCiphertext(
    const PublicKey& public_key,
    const Ciphertext& ciphertext) const
{
    if (ciphertext.u <= 0 ||
        ciphertext.u >= public_key.N_zeta_plus_one ||
        GCD(ciphertext.u, public_key.N_zeta_plus_one) != 1 ||
        ciphertext.e.size() != CamenischShoupEnc::CiphertextEComponentCount)
    {
        return false;
    }
    for (const NTL::ZZ& component : ciphertext.e)
    {
        if (component <= 0 ||
            component >= public_key.N_zeta_plus_one ||
            GCD(component, public_key.N_zeta_plus_one) != 1)
        {
            return false;
        }
    }
    return true;
}

bool CamenischShoupEncZKP::IsValidCommitment(
    const PublicKey& public_key,
    const Commitment& commitment) const
{
    const NTL::ZZ modulus = public_key.N * public_key.N;
    return commitment.value > 0 &&
        commitment.value < modulus &&
        GCD(commitment.value, modulus) == 1;
}
