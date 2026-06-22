#include <array>
#include <cstdlib>
#include <cstdint>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <NTL/ZZ.h>

#include "../CamenischShoup/CamenischShoupEnc.h"

namespace
{
std::string ToHex(const std::array<std::uint8_t, CamenischShoupEnc::HashBytes>& bytes)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const std::uint8_t byte : bytes)
    {
        out << std::setw(2) << static_cast<int>(byte);
    }
    return out.str();
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

bool ExpectEqual(const std::vector<NTL::ZZ>& actual, const std::vector<NTL::ZZ>& expected, const std::string& case_name)
{
    if (actual == expected)
    {
        std::cout << "[PASS] " << case_name << std::endl;
        return true;
    }

    std::cerr << "[FAIL] " << case_name << std::endl;
    std::cerr << "  expected:";
    for (const NTL::ZZ& value : expected)
    {
        std::cerr << ' ' << value;
    }
    std::cerr << std::endl;

    std::cerr << "  actual:  ";
    for (const NTL::ZZ& value : actual)
    {
        std::cerr << ' ' << value;
    }
    std::cerr << std::endl;
    return false;
}

std::vector<NTL::ZZ> MakePlaintext(std::initializer_list<long> values)
{
    std::vector<NTL::ZZ> plaintext;
    plaintext.reserve(values.size());
    for (const long value : values)
    {
        plaintext.emplace_back(NTL::ZZ(value));
    }
    return plaintext;
}

std::vector<NTL::ZZ> SlicePlaintext(const std::vector<NTL::ZZ>& plaintexts, std::uint32_t plaintext_index)
{
    std::vector<NTL::ZZ> slice;
    slice.reserve(CamenischShoupEnc::PlaintextValuesPerCiphertext);

    const std::uint32_t first_slot = plaintext_index * CamenischShoupEnc::PlaintextValuesPerCiphertext;
    for (std::uint32_t i = 0; i < CamenischShoupEnc::PlaintextValuesPerCiphertext && first_slot + i < plaintexts.size(); ++i)
    {
        slice.emplace_back(plaintexts[first_slot + i]);
    }

    return slice;
}

NTL::ZZ PackExpected(const CamenischShoupEnc::PublicKey& public_key, const std::vector<NTL::ZZ>& plaintext)
{
    NTL::ZZ packed(0);
    for (std::uint32_t i = 0; i < plaintext.size(); ++i)
    {
        packed += plaintext[i] * NTL::power(public_key.plaintext_packing_base, static_cast<long>(i));
    }
    return packed;
}
}

int main()
{
    CamenischShoupEnc enc;
    CamenischShoupEnc::PublicKey public_key;
    CamenischShoupEnc::SecretKey secret_key;
    CamenischShoupEnc::CommitmentKey commitment_key;

    std::cout << "Camenisch-Shoup encryption full test" << std::endl;
    std::cout << "Generating keys..." << std::endl;

    bool all_passed = true;

    std::array<std::uint8_t, CamenischShoupEnc::HashBytes> challenge{};
    enc.RandomOracle(challenge, "abc");
    all_passed = ExpectTrue(
        ToHex(challenge) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "RandomOracle SHA-256 challenge") && all_passed;

    enc.Setup(public_key);
    all_passed = ExpectTrue(public_key.N > 0, "Setup initializes N") && all_passed;
    all_passed = ExpectTrue(public_key.N_prime > 0, "Setup initializes N_prime") && all_passed;
    all_passed = ExpectTrue(public_key.N_zeta > 0, "Setup initializes N_zeta") && all_passed;
    all_passed = ExpectTrue(public_key.N_zeta_plus_one > 0, "Setup initializes N_zeta_plus_one") && all_passed;
    all_passed = ExpectEqual(public_key.T, public_key.N + 1, "Setup initializes T") && all_passed;
    all_passed = ExpectTrue(public_key.plaintext_packing_base > 1, "Setup initializes plaintext packing base") && all_passed;

    enc.GenerateKeys(public_key, secret_key, commitment_key);
    all_passed = ExpectTrue(public_key.g > 0, "GenerateKeys initializes encryption generator") && all_passed;
    all_passed = ExpectTrue(public_key.pk.size() == CamenischShoupEnc::CiphertextEComponentCount, "GenerateKeys initializes public key components") && all_passed;
    all_passed = ExpectTrue(secret_key.sk.size() == CamenischShoupEnc::CiphertextEComponentCount, "GenerateKeys initializes secret key components") && all_passed;
    all_passed = ExpectTrue(
        CamenischShoupEnc::CommitmentGeneratorCount == CamenischShoupEnc::PlaintextSlots * CamenischShoupEnc::CiphertextEComponentCount,
        "Commitment generator count matches plaintext layout") && all_passed;
    all_passed = ExpectTrue(commitment_key.g.size() == CamenischShoupEnc::CommitmentGeneratorCount, "GenerateKeys initializes commitment generators") && all_passed;
    for (std::uint32_t i = 0; i < commitment_key.g.size(); ++i)
    {
        all_passed = ExpectTrue(commitment_key.g[i] > 0, "GenerateKeys initializes each commitment generator") && all_passed;
    }
    all_passed = ExpectTrue(commitment_key.h > 0, "GenerateKeys initializes commitment h") && all_passed;

    enc.InitializeInputs(public_key, commitment_key);
    all_passed = ExpectTrue(
        enc.input_plaintexts.size() == CamenischShoupEnc::InputPlaintextCount * CamenischShoupEnc::PlaintextValuesPerCiphertext,
        "InitializeInputs creates plaintext set") && all_passed;
    all_passed = ExpectTrue(enc.input_encryption_randomness.size() == CamenischShoupEnc::InputPlaintextCount, "InitializeInputs creates encryption randomness set") && all_passed;
    all_passed = ExpectTrue(enc.input_ciphertexts.size() == CamenischShoupEnc::InputPlaintextCount, "InitializeInputs creates ciphertext set") && all_passed;
    all_passed = ExpectTrue(enc.input_commitment_randomness.size() == CamenischShoupEnc::InputPlaintextCount, "InitializeInputs creates commitment randomness set") && all_passed;
    all_passed = ExpectTrue(enc.input_commitments.size() == CamenischShoupEnc::InputPlaintextCount, "InitializeInputs creates commitment set") && all_passed;
    for (std::uint32_t i = 0; i < CamenischShoupEnc::InputPlaintextCount; ++i)
    {
        all_passed = ExpectTrue(enc.input_encryption_randomness[i] > 0, "InitializeInputs stores encryption randomness") && all_passed;
        all_passed = ExpectTrue(enc.input_ciphertexts[i].u > 0, "InitializeInputs stores ciphertext u") && all_passed;
        all_passed = ExpectTrue(enc.input_ciphertexts[i].e.size() == CamenischShoupEnc::CiphertextEComponentCount, "InitializeInputs stores ciphertext e components") && all_passed;
        all_passed = ExpectTrue(enc.input_commitment_randomness[i] > 0, "InitializeInputs stores commitment randomness") && all_passed;
        all_passed = ExpectTrue(enc.input_commitments[i].value > 0, "InitializeInputs stores commitment") && all_passed;

        std::vector<NTL::ZZ> initialized_plaintext;
        enc.Decrypt(public_key, secret_key, enc.input_ciphertexts[i], initialized_plaintext);
        all_passed = ExpectEqual(initialized_plaintext, SlicePlaintext(enc.input_plaintexts, i), "InitializeInputs ciphertext decrypts") && all_passed;
    }

    const std::vector<NTL::ZZ> first_plaintext = MakePlaintext({3, 5, 7, 11});
    const std::vector<NTL::ZZ> second_plaintext = MakePlaintext({2, 4, 6, 8});

    const NTL::ZZ fixed_commitment_randomness(54321);
    CamenischShoupEnc::Commitment fixed_commitment;
    CamenischShoupEnc::Commitment repeated_fixed_commitment;
    enc.GenerateCommitmentWithRandomness(
        public_key,
        commitment_key,
        first_plaintext,
        fixed_commitment_randomness,
        fixed_commitment);
    enc.GenerateCommitmentWithRandomness(
        public_key,
        commitment_key,
        first_plaintext,
        fixed_commitment_randomness,
        repeated_fixed_commitment);
    all_passed = ExpectTrue(
        fixed_commitment.value > 0 &&
            fixed_commitment == repeated_fixed_commitment,
        "GenerateCommitmentWithRandomness returns a deterministic Commitment") && all_passed;

    NTL::ZZ generated_commitment_randomness;
    CamenischShoupEnc::Commitment generated_commitment;
    enc.GenerateCommitment(
        public_key,
        commitment_key,
        first_plaintext,
        generated_commitment_randomness,
        generated_commitment);
    all_passed = ExpectTrue(
        generated_commitment_randomness > 0 &&
            generated_commitment.value > 0,
        "GenerateCommitment returns randomness and a Commitment") && all_passed;

    NTL::ZZ first_randomness;
    NTL::ZZ second_randomness;
    CamenischShoupEnc::Ciphertext first_ciphertext;
    CamenischShoupEnc::Ciphertext second_ciphertext;

    enc.Encrypt(public_key, first_plaintext, first_randomness, first_ciphertext);
    enc.Encrypt(public_key, second_plaintext, second_randomness, second_ciphertext);
    all_passed = ExpectTrue(first_randomness > 0, "Encrypt outputs randomness") && all_passed;
    all_passed = ExpectTrue(first_ciphertext.u > 0, "Encrypt outputs ciphertext u") && all_passed;
    all_passed = ExpectTrue(first_ciphertext.e.size() == CamenischShoupEnc::CiphertextEComponentCount, "Encrypt outputs ciphertext e components") && all_passed;

    std::vector<NTL::ZZ> decrypted;
    enc.Decrypt(public_key, secret_key, first_ciphertext, decrypted);
    all_passed = ExpectEqual(decrypted, first_plaintext, "encrypt/decrypt round trip") && all_passed;

    const NTL::ZZ fixed_randomness(12345);
    CamenischShoupEnc::Ciphertext fixed_ciphertext;
    CamenischShoupEnc::Ciphertext repeated_fixed_ciphertext;
    enc.EncryptWithRandomness(public_key, first_plaintext, fixed_randomness, fixed_ciphertext);
    enc.EncryptWithRandomness(public_key, first_plaintext, fixed_randomness, repeated_fixed_ciphertext);
    all_passed = ExpectEqual(fixed_ciphertext.u, repeated_fixed_ciphertext.u, "EncryptWithRandomness deterministic u") && all_passed;
    all_passed = ExpectTrue(fixed_ciphertext.e == repeated_fixed_ciphertext.e, "EncryptWithRandomness deterministic e") && all_passed;
    enc.Decrypt(public_key, secret_key, fixed_ciphertext, decrypted);
    all_passed = ExpectEqual(decrypted, first_plaintext, "EncryptWithRandomness decrypts") && all_passed;

    NTL::ZZ quotient;
    enc.LFunction(public_key, public_key.T, quotient);
    all_passed = ExpectEqual(quotient, NTL::ZZ(1), "LFunction computes (T - 1) / N") && all_passed;

    const NTL::ZZ packed_plaintext = PackExpected(public_key, first_plaintext);
    const NTL::ZZ encoded_plaintext = NTL::PowerMod(public_key.T, packed_plaintext, public_key.N_zeta_plus_one);
    NTL::ZZ decoded_plaintext;
    enc.DiscreteLog(public_key, encoded_plaintext, decoded_plaintext);
    all_passed = ExpectEqual(decoded_plaintext, packed_plaintext, "DiscreteLog decodes packed plaintext") && all_passed;

    CamenischShoupEnc::Ciphertext added_ciphertext;
    enc.HomomorphicAdd(public_key, added_ciphertext, first_ciphertext, second_ciphertext);
    enc.Decrypt(public_key, secret_key, added_ciphertext, decrypted);
    all_passed = ExpectEqual(decrypted, MakePlaintext({5, 9, 13, 19}), "homomorphic addition") && all_passed;

    CamenischShoupEnc::Ciphertext subtracted_ciphertext;
    enc.HomomorphicSubtract(public_key, subtracted_ciphertext, first_ciphertext, second_ciphertext);
    enc.Decrypt(public_key, secret_key, subtracted_ciphertext, decrypted);
    all_passed = ExpectEqual(decrypted, MakePlaintext({1, 1, 1, 3}), "homomorphic subtraction") && all_passed;

    CamenischShoupEnc::Ciphertext scaled_ciphertext;
    enc.ScalarMultiply(public_key, scaled_ciphertext, first_ciphertext, NTL::ZZ(3));
    enc.Decrypt(public_key, secret_key, scaled_ciphertext, decrypted);
    all_passed = ExpectEqual(decrypted, MakePlaintext({9, 15, 21, 33}), "scalar multiplication") && all_passed;

    if (!all_passed)
    {
        std::cerr << "Camenisch-Shoup encryption full test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Camenisch-Shoup encryption full test passed" << std::endl;
    return EXIT_SUCCESS;
}
