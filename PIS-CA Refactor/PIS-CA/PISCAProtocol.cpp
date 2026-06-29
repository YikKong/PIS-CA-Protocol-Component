#include "PISCAProtocol.h"

#include <stdexcept>
#include <sstream>
#include <unordered_set>

#include <openssl/bn.h>
#include <openssl/ec.h>

namespace
{
void ThrowIf(bool failed, const char* message)
{
    if (failed)
    {
        throw std::runtime_error(message);
    }
}

std::string ToString(const NTL::ZZ& value)
{
    std::ostringstream out;
    out << value;
    return out.str();
}

bool ContainsDuplicate(const std::vector<NTL::ZZ>& values)
{
    std::unordered_set<std::string> seen;
    for (const NTL::ZZ& value : values)
    {
        if (!seen.emplace(ToString(value)).second)
        {
            return true;
        }
    }
    return false;
}

std::vector<NTL::ZZ> ScalarPlaintext(const NTL::ZZ& value)
{
    return std::vector<NTL::ZZ>{value};
}

std::vector<NTL::ZZ> RepeatedSlotPlaintext(const NTL::ZZ& value)
{
    return std::vector<NTL::ZZ>(
        CamenischShoupEnc::PlaintextValuesPerCiphertext,
        value);
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

NTL::ZZ PowerOfTwo(std::uint32_t bit_count)
{
    NTL::ZZ value(1);
    value <<= bit_count;
    return value;
}

EC_POINT* DuplicatePoint(const EC_GROUP* group, const EC_POINT* point)
{
    return point == nullptr ? nullptr : EC_POINT_dup(point, group);
}

bool HasCamenischShoupCommitmentParameters(
    const CamenischShoupEnc::PublicKey& public_key,
    const CamenischShoupEnc::CommitmentKey& commitment_key)
{
    return public_key.N != 0 &&
        !commitment_key.g.empty() &&
        commitment_key.h != 0;
}

NTL::ZZ BignumToZZ(const BIGNUM* value)
{
    ThrowIf(value == nullptr, "BIGNUM value is null");

    const int byte_count = BN_num_bytes(value);
    std::vector<unsigned char> bytes(byte_count);
    BN_bn2bin(value, bytes.data());

    NTL::ZZ result(0);
    for (unsigned char byte : bytes)
    {
        result <<= 8;
        result += byte;
    }
    return result;
}

NTL::ZZ GenerateDoprfKey(const BIGNUM* elgamal_order)
{
    const NTL::ZZ q = BignumToZZ(elgamal_order);
    ThrowIf(q <= 1, "ElGamal group order is invalid");
    return NTL::RandomBnd(q - 1) + 1;
}

}

PISCAProtocol::PISCAProtocol()
    : camenisch_shoup_zkp_(camenisch_shoup_),
      elgamal_()
{
}

void PISCAProtocol::Setup(
    P1& p1,
    P2& p2) const
{
    camenisch_shoup_.Setup(p1.camenisch_shoup_public_key);
    camenisch_shoup_.GenerateKeys(
        p1.camenisch_shoup_public_key,
        p1.camenisch_shoup_secret_key,
        p1.camenisch_shoup_commitment_key);

    camenisch_shoup_.Setup(p2.camenisch_shoup_public_key);
    camenisch_shoup_.GenerateKeys(
        p2.camenisch_shoup_public_key,
        p2.camenisch_shoup_secret_key,
        p2.camenisch_shoup_commitment_key);

    elgamal_.GenerateKeys(
        p1.elgamal_public_key,
        p1.elgamal_secret_key,
        p1.elgamal_commitment_key);

    GenerateElGamalKeyPairWithSharedBase(
        p1.elgamal_public_key,
        p2.elgamal_public_key,
        p2.elgamal_secret_key);
    p2.elgamal_commitment_key = p1.elgamal_commitment_key;

    p1.k = GenerateDoprfKey(elgamal_.Order());
    p2.k = GenerateDoprfKey(elgamal_.Order());

    if (!p1.input.empty())
    {
        GenerateInputCommitments(
            p1.camenisch_shoup_public_key,
            p1.camenisch_shoup_commitment_key,
            p1.input,
            p1.input_commitments,
            p1.input_commitment_randomness);
    }

    if (!p2.input.empty())
    {
        GenerateInputCommitments(
            p2.camenisch_shoup_public_key,
            p2.camenisch_shoup_commitment_key,
            p2.input,
            p2.input_commitments,
            p2.input_commitment_randomness);
    }
}

bool PISCAProtocol::InitializeP1(
    const std::vector<NTL::ZZ>& x,
    const std::vector<NTL::ZZ>& v,
    P1& p1) const
{
    if (x.empty() || x.size() != v.size() || ContainsDuplicate(x))
    {
        return false;
    }

    p1.input = x;
    p1.values = v;
    p1.input_commitments.clear();
    p1.input_commitment_randomness.clear();
    if (HasCamenischShoupCommitmentParameters(
            p1.camenisch_shoup_public_key,
            p1.camenisch_shoup_commitment_key))
    {
        GenerateInputCommitments(
            p1.camenisch_shoup_public_key,
            p1.camenisch_shoup_commitment_key,
            p1.input,
            p1.input_commitments,
            p1.input_commitment_randomness);
    }
    return true;
}

bool PISCAProtocol::InitializeP2(
    const std::vector<NTL::ZZ>& y,
    P2& p2) const
{
    if (y.empty() || ContainsDuplicate(y))
    {
        return false;
    }

    p2.input = y;
    p2.input_commitments.clear();
    p2.input_commitment_randomness.clear();
    if (HasCamenischShoupCommitmentParameters(
            p2.camenisch_shoup_public_key,
            p2.camenisch_shoup_commitment_key))
    {
        GenerateInputCommitments(
            p2.camenisch_shoup_public_key,
            p2.camenisch_shoup_commitment_key,
            p2.input,
            p2.input_commitments,
            p2.input_commitment_randomness);
    }
    return true;
}

void PISCAProtocol::ExecuteRoundOne(
    PartyState& round_one_party,
    const PartyState& verifier_party) const
{
    GenerateRoundOneState(
        round_one_party.camenisch_shoup_public_key,
        verifier_party.camenisch_shoup_commitment_key,
        round_one_party.k,
        round_one_party.round_one);
}

bool PISCAProtocol::VerifyRoundOne(
    const PartyState& round_one_party,
    const PartyState& verifier_party) const
{
    return camenisch_shoup_zkp_.VerifyEncProofWithSlottedCommitments(
        round_one_party.camenisch_shoup_public_key,
        verifier_party.camenisch_shoup_commitment_key,
        round_one_party.round_one.message.k_ciphertext,
        round_one_party.round_one.message.k_commitments,
        round_one_party.round_one.message.k_proof_message);
}

void PISCAProtocol::ExecuteRoundTwo(
    PartyState& computation_party,
    const PartyState& input_party) const
{
    GenerateRoundTwoState(
        computation_party,
        input_party,
        computation_party.round_two);
}

bool PISCAProtocol::VerifyRoundTwo(
    const PartyState& computation_party,
    const PartyState& input_party) const
{
    return camenisch_shoup_zkp_.VerifyBatchBetaProof(
        input_party.camenisch_shoup_public_key,
        input_party.camenisch_shoup_commitment_key,
        elgamal_,
        computation_party.elgamal_public_key,
        computation_party.round_two.message.proof_message);
}

void PISCAProtocol::ExecuteRoundThree(
    PartyState& decryption_party,
    const PartyState& computation_party) const
{
    GenerateRoundThreeState(
        decryption_party,
        computation_party,
        decryption_party.round_three);
}

bool PISCAProtocol::VerifyRoundThree(
    const PartyState& decryption_party,
    const PartyState& computation_party) const
{
    return camenisch_shoup_zkp_.VerifyDecProof(
        decryption_party.camenisch_shoup_public_key,
        computation_party.camenisch_shoup_commitment_key,
        elgamal_,
        computation_party.elgamal_commitment_key,
        decryption_party.round_three.message.proof_message);
}

bool PISCAProtocol::CamenischShoupParametersAreIndependent(
    const P1& p1,
    const P2& p2) const
{
    return p1.camenisch_shoup_public_key.N !=
            p2.camenisch_shoup_public_key.N &&
        p1.camenisch_shoup_public_key.N_prime !=
            p2.camenisch_shoup_public_key.N_prime &&
        p1.camenisch_shoup_public_key.N_zeta_plus_one !=
            p2.camenisch_shoup_public_key.N_zeta_plus_one &&
        p1.camenisch_shoup_public_key.T !=
            p2.camenisch_shoup_public_key.T &&
        p1.camenisch_shoup_public_key.g !=
            p2.camenisch_shoup_public_key.g &&
        p1.camenisch_shoup_public_key.pk !=
            p2.camenisch_shoup_public_key.pk &&
        p1.camenisch_shoup_secret_key.sk !=
            p2.camenisch_shoup_secret_key.sk;
}

bool PISCAProtocol::CommitmentKeysAreIndependent(
    const P1& p1,
    const P2& p2) const
{
    const bool camenisch_shoup_commitment_keys_are_independent =
        p1.camenisch_shoup_commitment_key.h !=
            p2.camenisch_shoup_commitment_key.h &&
        p1.camenisch_shoup_commitment_key.g !=
            p2.camenisch_shoup_commitment_key.g;

    return camenisch_shoup_commitment_keys_are_independent;
}

bool PISCAProtocol::ElGamalBaseParametersAreShared(
    const P1& p1,
    const P2& p2) const
{
    return p1.elgamal_public_key.group == p2.elgamal_public_key.group &&
        elgamal_.PointsEqual(
            p1.elgamal_public_key.generator,
            p2.elgamal_public_key.generator) &&
        elgamal_.PointsEqual(
            p1.elgamal_public_key.g,
            p2.elgamal_public_key.g) &&
        elgamal_.PointsEqual(
            p1.elgamal_commitment_key.g,
            p2.elgamal_commitment_key.g) &&
        elgamal_.PointsEqual(
            p1.elgamal_commitment_key.h,
            p2.elgamal_commitment_key.h);
}

bool PISCAProtocol::ElGamalNonBaseParametersAreIndependent(
    const P1& p1,
    const P2& p2) const
{
    return BN_cmp(p1.elgamal_secret_key.sk, p2.elgamal_secret_key.sk) != 0 &&
        !elgamal_.PointsEqual(
            p1.elgamal_public_key.pk,
            p2.elgamal_public_key.pk);
}

void PISCAProtocol::GenerateElGamalKeyPairWithSharedBase(
    const ElGamalEnc::PublicKey& shared_public_key,
    ElGamalEnc::PublicKey& public_key,
    ElGamalEnc::SecretKey& secret_key) const
{
    ThrowIf(
        shared_public_key.group == nullptr ||
            shared_public_key.generator == nullptr ||
            shared_public_key.g == nullptr,
        "PIS-CA shared ElGamal parameters are not initialized");

    EC_POINT_free(public_key.generator);
    EC_POINT_free(public_key.g);
    EC_POINT_free(public_key.pk);
    public_key.group = shared_public_key.group;
    public_key.generator = DuplicatePoint(
        shared_public_key.group,
        shared_public_key.generator);
    public_key.g = DuplicatePoint(
        shared_public_key.group,
        shared_public_key.g);
    public_key.pk = EC_POINT_new(shared_public_key.group);
    ThrowIf(
        public_key.generator == nullptr ||
            public_key.g == nullptr ||
            public_key.pk == nullptr,
        "PIS-CA ElGamal public-key allocation failed");

    elgamal_.GenerateRandomScalar(secret_key.sk);

    BN_CTX* ctx = BN_CTX_new();
    ThrowIf(ctx == nullptr, "PIS-CA BN_CTX allocation failed");
    EC_POINT_mul(
        elgamal_.Group(),
        public_key.pk,
        nullptr,
        public_key.generator,
        secret_key.sk,
        ctx);
    BN_CTX_free(ctx);

}

void PISCAProtocol::GenerateInputCommitments(
    const CamenischShoupEnc::PublicKey& public_key,
    const CamenischShoupEnc::CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& input,
    std::vector<CamenischShoupEnc::Commitment>& commitments,
    std::vector<NTL::ZZ>& commitment_randomness) const
{
    commitments.clear();
    commitment_randomness.clear();
    commitments.reserve(input.size());
    commitment_randomness.reserve(input.size());

    for (std::uint32_t i = 0; i < input.size(); ++i)
    {
        NTL::ZZ randomness;
        CamenischShoupEnc::Commitment commitment;
        camenisch_shoup_.GenerateCommitment(
            public_key,
            commitment_key,
            SlottedPlaintext(input[i], i),
            randomness,
            commitment);
        commitment_randomness.emplace_back(randomness);
        commitments.emplace_back(commitment);
    }
}

void PISCAProtocol::GenerateRoundOneState(
    const CamenischShoupEnc::PublicKey& encryption_public_key,
    const CamenischShoupEnc::CommitmentKey& commitment_key,
    const NTL::ZZ& k,
    RoundOneState& state) const
{
    ThrowIf(
        k <= 0,
        "PIS-CA round one key is not initialized");
    ThrowIf(
        !HasCamenischShoupCommitmentParameters(
            encryption_public_key,
            commitment_key),
        "PIS-CA round one Camenisch-Shoup parameters are not initialized");

    const std::vector<NTL::ZZ> ciphertext_plaintext = ScalarPlaintext(k);
    const std::uint32_t slot_count =
        CamenischShoupEnc::PlaintextValuesPerCiphertext;
    state = RoundOneState{};
    state.witness.k = k;

    camenisch_shoup_.Encrypt(
        encryption_public_key,
        ciphertext_plaintext,
        state.witness.encryption_randomness,
        state.message.k_ciphertext);

    state.message.k_commitments.reserve(slot_count);
    state.witness.commitment_randomness.reserve(slot_count);
    for (std::uint32_t slot_index = 0; slot_index < slot_count; ++slot_index)
    {
        NTL::ZZ randomness;
        CamenischShoupEnc::Commitment commitment;
        camenisch_shoup_.GenerateCommitment(
            encryption_public_key,
            commitment_key,
            SlottedPlaintext(k, slot_index),
            randomness,
            commitment);
        state.witness.commitment_randomness.emplace_back(randomness);
        state.message.k_commitments.emplace_back(commitment);
    }

    camenisch_shoup_zkp_.CreateEncProofWithSlottedCommitments(
        encryption_public_key,
        commitment_key,
        k,
        state.message.k_ciphertext,
        state.witness.encryption_randomness,
        state.witness.commitment_randomness,
        state.message.k_commitments,
        state.witness.k_proof);
    state.message.k_proof_message = state.witness.k_proof.message;
}

void PISCAProtocol::GenerateRoundTwoState(
    const PartyState& computation_party,
    const PartyState& input_party,
    RoundTwoState& state) const
{
    ThrowIf(computation_party.input.empty(), "PIS-CA round two input is not initialized");
    ThrowIf(computation_party.k <= 0, "PIS-CA round two computation-party key is not initialized");
    ThrowIf(input_party.k <= 0, "PIS-CA round two input-party key is not initialized");
    ThrowIf(
        !HasCamenischShoupCommitmentParameters(
            input_party.camenisch_shoup_public_key,
            input_party.camenisch_shoup_commitment_key),
        "PIS-CA batch beta Camenisch-Shoup parameters are not initialized");
    ThrowIf(
        !elgamal_.IsValidPublicKey(computation_party.elgamal_public_key),
        "PIS-CA batch beta ElGamal public key is not initialized");

    const NTL::ZZ q = BignumToZZ(elgamal_.Order());
    ThrowIf(q <= 1, "PIS-CA batch beta ElGamal order is invalid");

    const std::uint32_t slot_count =
        CamenischShoupEnc::PlaintextValuesPerCiphertext;
    const std::uint32_t output_count =
        static_cast<std::uint32_t>(
            (computation_party.input.size() + slot_count - 1) / slot_count);
    const std::uint32_t padded_count = output_count * slot_count;

    state = RoundTwoState{};
    RoundTwoWitness& witness = state.witness;
    witness.k = computation_party.k;
    witness.input = computation_party.input;
    NTL::ZZ a_bound = PowerOfTwo(CamenischShoupEncZKP::RangeSecurityBits);
    if (a_bound > q)
    {
        a_bound = q;
    }
    ThrowIf(a_bound <= 0, "PIS-CA batch beta coefficient bound is invalid");
    witness.a.reserve(padded_count);
    witness.alpha.reserve(padded_count);
    witness.b.reserve(padded_count);
    for (std::uint32_t i = 0; i < padded_count; ++i)
    {
        const NTL::ZZ input_i =
            i < witness.input.size() ? witness.input[i] : NTL::ZZ(0);
        const NTL::ZZ a_i = NTL::RandomBnd(a_bound);
        const NTL::ZZ b_i = NTL::RandomBnd(q);
        witness.a.emplace_back(a_i);
        witness.alpha.emplace_back(a_i * (witness.k + input_i));
        witness.b.emplace_back(b_i);
    }

    witness.a_commitment_randomness.reserve(output_count);
    witness.alpha_commitment_randomness.reserve(output_count);
    witness.b_commitment_randomness.reserve(output_count);
    witness.encryption_randomness.reserve(output_count);
    for (std::uint32_t i = 0; i < output_count; ++i)
    {
        NTL::ZZ randomness;
        NTL::RandomBits(randomness, 2 * CamenischShoupEnc::PrimeBits);
        witness.a_commitment_randomness.emplace_back(randomness);
        NTL::RandomBits(randomness, 2 * CamenischShoupEnc::PrimeBits);
        witness.alpha_commitment_randomness.emplace_back(randomness);
        NTL::RandomBits(randomness, 2 * CamenischShoupEnc::PrimeBits);
        witness.b_commitment_randomness.emplace_back(randomness);
        NTL::RandomBits(randomness, 2 * CamenischShoupEnc::PrimeBits);
        witness.encryption_randomness.emplace_back(randomness);
    }

    camenisch_shoup_zkp_.CreateBatchBetaCiphertextsAndProof(
        input_party.camenisch_shoup_public_key,
        input_party.camenisch_shoup_commitment_key,
        elgamal_,
        computation_party.elgamal_public_key,
        input_party.round_one.message.k_ciphertext,
        q,
        witness.a,
        witness.alpha,
        witness.b,
        witness.a_commitment_randomness,
        witness.alpha_commitment_randomness,
        witness.b_commitment_randomness,
        witness.encryption_randomness,
        witness.proof);
    state.message.proof_message = witness.proof.message;
}

void PISCAProtocol::GenerateRoundThreeState(
    const PartyState& decryption_party,
    const PartyState& computation_party,
    RoundThreeState& state) const
{
    ThrowIf(
        !HasCamenischShoupCommitmentParameters(
            decryption_party.camenisch_shoup_public_key,
            computation_party.camenisch_shoup_commitment_key),
        "PIS-CA round three Camenisch-Shoup parameters are not initialized");
    ThrowIf(
        decryption_party.camenisch_shoup_secret_key.sk.size() !=
            CamenischShoupEnc::CiphertextEComponentCount,
        "PIS-CA round three Camenisch-Shoup secret key is not initialized");
    ThrowIf(
        computation_party.round_two.message.proof_message.beta_ciphertexts.empty(),
        "PIS-CA round three beta ciphertexts are not initialized");
    ThrowIf(
        !elgamal_.IsValidCommitmentKey(computation_party.elgamal_commitment_key),
        "PIS-CA round three ElGamal commitment key is not initialized");

    state = RoundThreeState{};
    camenisch_shoup_zkp_.CreateDecProofAndCommitments(
        decryption_party.camenisch_shoup_public_key,
        decryption_party.camenisch_shoup_secret_key,
        computation_party.camenisch_shoup_commitment_key,
        elgamal_,
        computation_party.elgamal_commitment_key,
        computation_party.round_two.message.proof_message.beta_ciphertexts,
        state.witness.proof);
    state.message.proof_message = state.witness.proof.message;
}
