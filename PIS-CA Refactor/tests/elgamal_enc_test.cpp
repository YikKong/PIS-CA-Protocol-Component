#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

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

BIGNUM* MakeScalar(unsigned long value)
{
    BIGNUM* scalar = BN_new();
    if (scalar == nullptr || BN_set_word(scalar, value) != 1)
    {
        BN_free(scalar);
        throw std::runtime_error("test scalar allocation failed");
    }
    return scalar;
}
}

int main()
{
    ElGamalEnc enc;
    ElGamalEnc::PublicKey public_key;
    ElGamalEnc::SecretKey secret_key;
    enc.Setup(public_key);
    enc.GenerateKeys(public_key, secret_key);

    bool all_passed = true;
    all_passed = ExpectTrue(enc.IsValidPublicKey(public_key), "key generation") && all_passed;

    BIGNUM* seven = MakeScalar(7);
    BIGNUM* eleven = MakeScalar(11);
    BIGNUM* three = MakeScalar(3);
    BIGNUM* first_randomness = BN_new();
    BIGNUM* second_randomness = BN_new();
    EC_POINT* first_plaintext = enc.NewPoint();
    EC_POINT* second_plaintext = enc.NewPoint();
    EC_POINT* decrypted = enc.NewPoint();
    EC_POINT* expected = enc.NewPoint();

    enc.EncodePlaintext(public_key, seven, first_plaintext);
    enc.EncodePlaintext(public_key, eleven, second_plaintext);

    ElGamalEnc::Ciphertext first_ciphertext;
    ElGamalEnc::Ciphertext second_ciphertext;
    enc.Encrypt(public_key, first_plaintext, first_randomness, first_ciphertext);
    enc.Encrypt(public_key, second_plaintext, second_randomness, second_ciphertext);
    all_passed = ExpectTrue(enc.IsValidCiphertext(first_ciphertext), "encryption") && all_passed;

    enc.Decrypt(public_key, secret_key, first_ciphertext, decrypted);
    all_passed = ExpectTrue(
        enc.PointsEqual(decrypted, first_plaintext),
        "encrypt/decrypt round trip") && all_passed;

    ElGamalEnc::Ciphertext repeated_ciphertext;
    enc.EncryptWithRandomness(
        public_key,
        first_plaintext,
        first_randomness,
        repeated_ciphertext);
    all_passed = ExpectTrue(
        enc.PointsEqual(first_ciphertext.u, repeated_ciphertext.u) &&
            enc.PointsEqual(first_ciphertext.e, repeated_ciphertext.e),
        "EncryptWithRandomness is deterministic") && all_passed;

    ElGamalEnc::Ciphertext added;
    enc.HomomorphicAdd(public_key, added, first_ciphertext, second_ciphertext);
    enc.Decrypt(public_key, secret_key, added, decrypted);
    BIGNUM* eighteen = MakeScalar(18);
    enc.EncodePlaintext(public_key, eighteen, expected);
    all_passed = ExpectTrue(enc.PointsEqual(decrypted, expected), "homomorphic addition") && all_passed;

    ElGamalEnc::Ciphertext subtracted;
    enc.HomomorphicSubtract(public_key, subtracted, second_ciphertext, first_ciphertext);
    enc.Decrypt(public_key, secret_key, subtracted, decrypted);
    BIGNUM* four = MakeScalar(4);
    enc.EncodePlaintext(public_key, four, expected);
    all_passed = ExpectTrue(enc.PointsEqual(decrypted, expected), "homomorphic subtraction") && all_passed;

    ElGamalEnc::Ciphertext scaled;
    enc.ScalarMultiply(public_key, scaled, first_ciphertext, three);
    enc.Decrypt(public_key, secret_key, scaled, decrypted);
    BIGNUM* twenty_one = MakeScalar(21);
    enc.EncodePlaintext(public_key, twenty_one, expected);
    all_passed = ExpectTrue(enc.PointsEqual(decrypted, expected), "scalar multiplication") && all_passed;

    BN_free(seven);
    BN_free(eleven);
    BN_free(three);
    BN_free(eighteen);
    BN_free(four);
    BN_free(twenty_one);
    BN_clear_free(first_randomness);
    BN_clear_free(second_randomness);
    EC_POINT_free(first_plaintext);
    EC_POINT_free(second_plaintext);
    EC_POINT_free(decrypted);
    EC_POINT_free(expected);

    if (!all_passed)
    {
        return EXIT_FAILURE;
    }
    std::cout << "ElGamal encryption full test passed" << std::endl;
    return EXIT_SUCCESS;
}
