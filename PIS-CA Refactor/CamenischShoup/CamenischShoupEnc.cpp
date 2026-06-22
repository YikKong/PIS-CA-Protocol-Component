#include "CamenischShoupEnc.h"

#include <algorithm>
#include <iostream>

#include <openssl/sha.h>

static const NTL::ZZ One(1);
static const NTL::ZZ Zero(0);
static const NTL::ZZ Two(2);
static const NTL::ZZ SubPlaintextLensAsZZ(CamenischShoupEnc::SubPlaintextLens);

NTL::ZZ CamenischShoupEnc::PackPlaintextSlots(const PublicKey& public_key, const std::vector<NTL::ZZ>& plaintext, std::uint32_t component_index) const
{
    NTL::ZZ packed = Zero;
    const std::uint32_t first_slot = component_index * PlaintextSlots;

    for (std::uint32_t i = 0; i < PlaintextSlots && first_slot + i < plaintext.size(); ++i) 
    {
        NTL::ZZ weighted_plaintext;
        mul(weighted_plaintext, plaintext[first_slot + i], power(public_key.plaintext_packing_base, i));
        add(packed, packed, weighted_plaintext);
    }

    return packed;
}

void CamenischShoupEnc::UnpackPlaintextSlots(const PublicKey& public_key, NTL::ZZ packed_plaintext, std::vector<NTL::ZZ>& plaintext) const
{
    for (std::uint32_t i = 0; i < PlaintextSlots; ++i) 
    {
        NTL::ZZ plaintext_part;
        div(plaintext_part, packed_plaintext, power(public_key.plaintext_packing_base, PlaintextSlots - i - 1));
        plaintext.emplace_back(plaintext_part);

        NTL::ZZ weighted_plaintext_part;
        mul(weighted_plaintext_part, plaintext_part, power(public_key.plaintext_packing_base, PlaintextSlots - i - 1));
        sub(packed_plaintext, packed_plaintext, weighted_plaintext_part);
    }

    std::reverse(plaintext.end() - PlaintextSlots, plaintext.end());
}

void CamenischShoupEnc::RandomOracle(std::array<std::uint8_t, HashBytes>& challenge, const std::string& input) const
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input.data(), input.size());
    SHA256_Final(challenge.data(), &ctx);
}

void CamenischShoupEnc::Setup(PublicKey& public_key) const
{
    NTL::ZZ p, q;

    GenGermainPrime(p, PrimeBits);
    GenGermainPrime(q, PrimeBits);

    public_key.N = p * q;
    public_key.N_prime = ((p - 1) / 2) * ((q - 1) / 2);
    public_key.N_zeta = 1;
    public_key.N_zeta_plus_one = public_key.N;

    for (std::uint32_t i = 1; i <= Zeta; ++i) 
    {
        public_key.N_zeta *= public_key.N;
        public_key.N_zeta_plus_one *= public_key.N;
    }

    public_key.T = AddMod(One, public_key.N, public_key.N_zeta_plus_one);
    public_key.plaintext_packing_base = PowerMod(Two, SubPlaintextLensAsZZ - 5, public_key.N_zeta_plus_one);
}

void CamenischShoupEnc::GenerateKeys(PublicKey& public_key, SecretKey& secret_key, CommitmentKey& commitment_key) const
{
    NTL::ZZ generator_seed;

    while (true) 
    {
        RandomLen(generator_seed, 2 * PrimeBits - 2);
        if (GCD(generator_seed, public_key.N_zeta_plus_one) == 1) 
        {
            break;
        }
    }

    public_key.g = PowerMod(generator_seed, 2 * public_key.N_zeta, public_key.N_zeta_plus_one);

    secret_key.sk.clear();
    secret_key.sk.reserve(CiphertextEComponentCount);
    public_key.pk.clear();
    public_key.pk.reserve(CiphertextEComponentCount);
    for (std::uint32_t i = 0; i < CiphertextEComponentCount; ++i) 
    {
        NTL::ZZ secret_exponent;
        RandomBits(secret_exponent, 2 * PrimeBits - 2);
        secret_key.sk.emplace_back(secret_exponent);
        public_key.pk.emplace_back(PowerMod(public_key.g, secret_exponent, public_key.N_zeta_plus_one));
    }

    commitment_key.g.clear();
    commitment_key.g.reserve(CommitmentGeneratorCount);
    for (std::uint32_t i = 0; i < CommitmentGeneratorCount; ++i)
    {
        NTL::ZZ commitment_generator;
        while (true) 
        {
            RandomBits(commitment_generator, 2 * PrimeBits - 2);
            if (PowerMod(commitment_generator, public_key.N_prime, public_key.N) == 1) 
            {
                break;
            }
        }
        commitment_key.g.emplace_back(commitment_generator);
    }

    while (true) 
    {
        RandomBits(commitment_key.h, 2 * PrimeBits - 2);
        if (PowerMod(commitment_key.h, public_key.N_prime, public_key.N) == 1) 
        {
            break;
        }
    }
}

void CamenischShoupEnc::InitializeInputs(const PublicKey& public_key, const CommitmentKey& commitment_key)
{
    input_plaintexts.clear();
    input_plaintexts.reserve(InputPlaintextCount * PlaintextValuesPerCiphertext);
    for (std::uint32_t i = 0; i < InputPlaintextCount * PlaintextValuesPerCiphertext; ++i)
    {
        NTL::ZZ plaintext;
        RandomBits(plaintext, SubPlaintextLens - 10);
        input_plaintexts.emplace_back(plaintext);
    }

    input_encryption_randomness.clear();
    input_encryption_randomness.reserve(InputPlaintextCount);
    input_ciphertexts.clear();
    input_ciphertexts.reserve(InputPlaintextCount);
    for (std::uint32_t plaintext_index = 0; plaintext_index < InputPlaintextCount; ++plaintext_index)
    {
        NTL::ZZ randomness;
        Ciphertext ciphertext;
        Encrypt(public_key, PlaintextSlice(input_plaintexts, plaintext_index), randomness, ciphertext);

        input_encryption_randomness.emplace_back(randomness);
        input_ciphertexts.emplace_back(ciphertext);
    }

    input_commitment_randomness.clear();
    input_commitment_randomness.reserve(InputPlaintextCount);
    input_commitments.clear();
    input_commitments.reserve(InputPlaintextCount);
    for (std::uint32_t plaintext_index = 0; plaintext_index < InputPlaintextCount; ++plaintext_index)
    {
        NTL::ZZ randomness;
        RandomBits(randomness, NumBits(public_key.N) - 10);

        input_commitment_randomness.emplace_back(randomness);
        Commitment commitment;
        GenerateCommitmentWithRandomness(
            public_key,
            commitment_key,
            PlaintextSlice(input_plaintexts, plaintext_index),
            randomness,
            commitment);
        input_commitments.emplace_back(commitment);
    }
}

void CamenischShoupEnc::Encrypt(const PublicKey& public_key, const std::vector<NTL::ZZ>& plaintext, NTL::ZZ& randomness, Ciphertext& ciphertext) const
{
    RandomBits(randomness, 2 * PrimeBits - 2);
    EncryptWithRandomness(public_key, plaintext, randomness, ciphertext);
}

void CamenischShoupEnc::EncryptWithRandomness(const PublicKey& public_key, const std::vector<NTL::ZZ>& plaintext, const NTL::ZZ& randomness, Ciphertext& ciphertext) const
{
    if (plaintext.size() > PlaintextValuesPerCiphertext)
    {
        std::cout << "encrypt plaintext size error " << std::endl;
        return;
    }

    if (public_key.pk.size() != CiphertextEComponentCount) 
    {
        std::cout << "public key component count error " << std::endl;
        return;
    }

    ciphertext.u = PowerMod(public_key.g, randomness, public_key.N_zeta_plus_one);
    ciphertext.e.clear();
    ciphertext.e.reserve(CiphertextEComponentCount);

    for (std::uint32_t i = 0; i < CiphertextEComponentCount; ++i) 
    {
        const NTL::ZZ packed_plaintext = PackPlaintextSlots(public_key, plaintext, i);
        const NTL::ZZ encoded_plaintext = PowerMod(public_key.T, packed_plaintext, public_key.N_zeta_plus_one);

        NTL::ZZ e_component = PowerMod(public_key.pk[i], randomness, public_key.N_zeta_plus_one);
        e_component = MulMod(e_component, encoded_plaintext, public_key.N_zeta_plus_one);
        ciphertext.e.emplace_back(e_component);
    }
}

std::vector<NTL::ZZ> CamenischShoupEnc::PlaintextSlice(const std::vector<NTL::ZZ>& plaintexts, std::uint32_t plaintext_index) const
{
    std::vector<NTL::ZZ> slice;
    slice.reserve(PlaintextValuesPerCiphertext);

    const std::uint32_t first_slot = plaintext_index * PlaintextValuesPerCiphertext;
    for (std::uint32_t slot_index = 0; slot_index < PlaintextValuesPerCiphertext && first_slot + slot_index < plaintexts.size(); ++slot_index)
    {
        slice.emplace_back(plaintexts[first_slot + slot_index]);
    }

    return slice;
}

void CamenischShoupEnc::GenerateCommitment(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& plaintext,
    NTL::ZZ& randomness,
    Commitment& commitment) const
{
    RandomBits(randomness, NumBits(public_key.N) - 10);
    GenerateCommitmentWithRandomness(
        public_key,
        commitment_key,
        plaintext,
        randomness,
        commitment);
}

void CamenischShoupEnc::GenerateCommitmentWithRandomness(
    const PublicKey& public_key,
    const CommitmentKey& commitment_key,
    const std::vector<NTL::ZZ>& plaintext,
    const NTL::ZZ& randomness,
    Commitment& commitment) const
{
    if (plaintext.size() > PlaintextValuesPerCiphertext ||
        commitment_key.g.size() < CommitmentGeneratorCount)
    {
        std::cout << "commitment input size error " << std::endl;
        return;
    }

    const NTL::ZZ commitment_modulus = public_key.N * public_key.N;
    commitment.value = PowerMod(commitment_key.h, randomness, commitment_modulus);

    for (std::uint32_t component_index = 0; component_index < CiphertextEComponentCount; ++component_index)
    {
        const std::uint32_t component_first_slot = component_index * PlaintextSlots;
        const std::uint32_t generator_first_slot = component_index * PlaintextSlots;
        for (std::uint32_t slot_index = 0; slot_index < PlaintextSlots && component_first_slot + slot_index < plaintext.size(); ++slot_index)
        {
            const NTL::ZZ commitment_factor = PowerMod(
                commitment_key.g[generator_first_slot + slot_index],
                plaintext[component_first_slot + slot_index],
                commitment_modulus);
            commitment.value = MulMod(commitment.value, commitment_factor, commitment_modulus);
        }
    }
}

void CamenischShoupEnc::LFunction(const PublicKey& public_key, const NTL::ZZ& encoded_value, NTL::ZZ& quotient) const
{
    div(quotient, encoded_value - 1, public_key.N);
}

void CamenischShoupEnc::DiscreteLog(const PublicKey& public_key, const NTL::ZZ& encoded_plaintext, NTL::ZZ& plaintext) const
{
    NTL::ZZ plaintext_mod_power = Zero;

    for (std::uint32_t modulus_power = 1; modulus_power <= Zeta; ++modulus_power) 
    {
        NTL::ZZ current_modulus = One;
        NTL::ZZ lower_modulus_factor = One;
        NTL::ZZ factorial_term = One;
        NTL::ZZ log_candidate;

        LFunction(public_key, encoded_plaintext, log_candidate);
        NTL::ZZ previous_plaintext = plaintext_mod_power;

        for (std::uint32_t power_index = 1; power_index <= modulus_power; ++power_index) 
        {
            current_modulus *= public_key.N;
        }

        for (std::uint32_t expansion_degree = 2; expansion_degree <= modulus_power; ++expansion_degree) 
        {
            for (std::uint32_t factor_index = 1; factor_index < expansion_degree; ++factor_index) 
            {
                lower_modulus_factor *= public_key.N;
                factorial_term = factor_index * factorial_term;
            }

            factorial_term *= expansion_degree;
            plaintext_mod_power -= 1;
            previous_plaintext = MulMod(previous_plaintext, plaintext_mod_power, current_modulus);

            NTL::ZZ binomial_correction = MulMod(previous_plaintext, lower_modulus_factor, current_modulus);
            const NTL::ZZ inverse_factorial = InvMod(factorial_term, current_modulus);
            binomial_correction = MulMod(binomial_correction, inverse_factorial, current_modulus);
            log_candidate = SubMod(log_candidate, binomial_correction, current_modulus);
        }

        plaintext_mod_power = log_candidate;
    }

    plaintext = plaintext_mod_power;
}

void CamenischShoupEnc::Decrypt(const PublicKey& public_key, const SecretKey& secret_key, const Ciphertext& ciphertext, std::vector<NTL::ZZ>& plaintext) const
{
    if (ciphertext.e.size() != CiphertextEComponentCount || secret_key.sk.size() != CiphertextEComponentCount) 
    {
        std::cout << "ciphertext component count error " << std::endl;
        return;
    }

    plaintext.clear();
    plaintext.reserve(PlaintextValuesPerCiphertext);
    for (std::uint32_t i = 0; i < CiphertextEComponentCount; ++i) 
    {
        NTL::ZZ encoded_plaintext = InvMod(ciphertext.u, public_key.N_zeta_plus_one);
        encoded_plaintext = PowerMod(encoded_plaintext, secret_key.sk[i], public_key.N_zeta_plus_one);
        encoded_plaintext = MulMod(ciphertext.e[i], encoded_plaintext, public_key.N_zeta_plus_one);

        NTL::ZZ packed_plaintext;
        DiscreteLog(public_key, encoded_plaintext, packed_plaintext);
        UnpackPlaintextSlots(public_key, packed_plaintext, plaintext);
    }
}

void CamenischShoupEnc::HomomorphicAdd(const PublicKey& public_key, Ciphertext& result, const Ciphertext& left, const Ciphertext& right) const
{
    if (left.e.size() != CiphertextEComponentCount || right.e.size() != CiphertextEComponentCount) 
    {
        std::cout << "ciphertext component count error " << std::endl;
        return;
    }

    result.u = MulMod(left.u, right.u, public_key.N_zeta_plus_one);
    result.e.clear();
    result.e.reserve(CiphertextEComponentCount);
    for (std::uint32_t i = 0; i < CiphertextEComponentCount; ++i) 
    {
        result.e.emplace_back(MulMod(left.e[i], right.e[i], public_key.N_zeta_plus_one));
    }
}

void CamenischShoupEnc::HomomorphicSubtract(const PublicKey& public_key, Ciphertext& result, const Ciphertext& left, const Ciphertext& right) const
{
    if (left.e.size() != CiphertextEComponentCount || right.e.size() != CiphertextEComponentCount) 
    {
        std::cout << "ciphertext component count error " << std::endl;
        return;
    }

    const NTL::ZZ inverse_u = InvMod(right.u, public_key.N_zeta_plus_one);

    result.u = MulMod(left.u, inverse_u, public_key.N_zeta_plus_one);
    result.e.clear();
    result.e.reserve(CiphertextEComponentCount);
    for (std::uint32_t i = 0; i < CiphertextEComponentCount; ++i) 
    {
        const NTL::ZZ inverse_e = InvMod(right.e[i], public_key.N_zeta_plus_one);
        result.e.emplace_back(MulMod(left.e[i], inverse_e, public_key.N_zeta_plus_one));
    }
}

void CamenischShoupEnc::ScalarMultiply(const PublicKey& public_key, Ciphertext& result, const Ciphertext& ciphertext, const NTL::ZZ& scalar) const
{
    if (ciphertext.e.size() != CiphertextEComponentCount) 
    {
        std::cout << "ciphertext component count error " << std::endl;
        return;
    }

    result.u = PowerMod(ciphertext.u, scalar, public_key.N_zeta_plus_one);
    result.e.clear();
    result.e.reserve(CiphertextEComponentCount);
    for (std::uint32_t i = 0; i < CiphertextEComponentCount; ++i) 
    {
        result.e.emplace_back(PowerMod(ciphertext.e[i], scalar, public_key.N_zeta_plus_one));
    }
}
