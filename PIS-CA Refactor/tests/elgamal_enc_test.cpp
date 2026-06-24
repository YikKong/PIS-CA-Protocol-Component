#include <array>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "../ElGamal/ElGamalEnc.h"

namespace
{
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
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

bool ExpectThrows(
    const std::function<void()>& operation,
    const std::string& case_name)
{
    try
    {
        operation();
    }
    catch (const std::exception&)
    {
        return ExpectTrue(true, case_name);
    }
    return ExpectTrue(false, case_name);
}

BnPtr MakeScalar(unsigned long value)
{
    BnPtr scalar(BN_new(), BN_clear_free);
    if (scalar == nullptr || BN_set_word(scalar.get(), value) != 1)
    {
        throw std::runtime_error("test scalar allocation failed");
    }
    return scalar;
}

bool CiphertextsEqual(
    const ElGamalEnc& enc,
    const ElGamalEnc::Ciphertext& left,
    const ElGamalEnc::Ciphertext& right)
{
    return enc.PointsEqual(left.u, right.u) &&
        enc.PointsEqual(left.e, right.e);
}
}

int main()
{
    bool all_passed = true;

    ElGamalEnc enc;
    all_passed = ExpectTrue(
        enc.Group() != nullptr &&
            enc.Order() != nullptr &&
            !BN_is_zero(enc.Order()),
        "curve group and order accessors") && all_passed;

    PointPtr allocated_point(enc.NewPoint(), EC_POINT_free);
    all_passed = ExpectTrue(
        allocated_point != nullptr,
        "NewPoint allocates a curve point") && all_passed;

    std::array<std::uint8_t, ElGamalEnc::HashBytes> first_hash{};
    std::array<std::uint8_t, ElGamalEnc::HashBytes> repeated_hash{};
    std::array<std::uint8_t, ElGamalEnc::HashBytes> different_hash{};
    enc.RandomOracle(first_hash, "ElGamal test transcript");
    enc.RandomOracle(repeated_hash, "ElGamal test transcript");
    enc.RandomOracle(different_hash, "different transcript");
    all_passed = ExpectTrue(
        first_hash == repeated_hash && first_hash != different_hash,
        "RandomOracle is deterministic and input binding") && all_passed;

    ElGamalEnc::PublicKey setup_key;
    enc.Setup(setup_key);
    all_passed = ExpectTrue(
        setup_key.group == enc.Group() &&
            setup_key.generator != nullptr &&
            setup_key.g != nullptr &&
            setup_key.pk != nullptr &&
            EC_POINT_is_at_infinity(enc.Group(), setup_key.pk) == 1 &&
            !enc.IsValidPublicKey(setup_key),
        "Setup initializes an unkeyed public-key object") && all_passed;

    ElGamalEnc::PublicKey public_key;
    ElGamalEnc::SecretKey secret_key;
    ElGamalEnc::CommitmentKey commitment_key;
    enc.GenerateKeys(public_key, secret_key, commitment_key);
    all_passed = ExpectTrue(
        enc.IsValidPublicKey(public_key) &&
            secret_key.sk != nullptr &&
            !BN_is_zero(secret_key.sk),
        "GenerateKeys creates a valid ElGamal key pair") && all_passed;
    all_passed = ExpectTrue(
        enc.IsValidCommitmentKey(commitment_key) &&
            !enc.PointsEqual(commitment_key.g, commitment_key.h),
        "GenerateKeys creates independent commitment generators g and h") &&
        all_passed;

    ElGamalEnc::PublicKey encryption_only_public_key;
    ElGamalEnc::SecretKey encryption_only_secret_key;
    enc.GenerateKeys(encryption_only_public_key, encryption_only_secret_key);
    all_passed = ExpectTrue(
        enc.IsValidPublicKey(encryption_only_public_key),
        "two-argument GenerateKeys remains valid") && all_passed;

    BnPtr random_scalar(BN_new(), BN_clear_free);
    enc.GenerateRandomScalar(random_scalar.get());
    all_passed = ExpectTrue(
        !BN_is_zero(random_scalar.get()) &&
            !BN_is_negative(random_scalar.get()) &&
            BN_cmp(random_scalar.get(), enc.Order()) < 0,
        "GenerateRandomScalar returns a nonzero scalar modulo the group order") &&
        all_passed;

    PointPtr random_group_element(enc.NewPoint(), EC_POINT_free);
    PointPtr subgroup_check(enc.NewPoint(), EC_POINT_free);
    CtxPtr test_ctx(BN_CTX_new(), BN_CTX_free);
    enc.GenerateRandomGroupElement(random_group_element.get());
    const bool subgroup_mul_ok = EC_POINT_mul(
        enc.Group(),
        subgroup_check.get(),
        nullptr,
        random_group_element.get(),
        enc.Order(),
        test_ctx.get()) == 1;
    all_passed = ExpectTrue(
        EC_POINT_is_on_curve(
            enc.Group(),
            random_group_element.get(),
            test_ctx.get()) == 1 &&
            EC_POINT_is_at_infinity(
                enc.Group(),
                random_group_element.get()) == 0 &&
            subgroup_mul_ok &&
            EC_POINT_is_at_infinity(
                enc.Group(),
                subgroup_check.get()) == 1,
        "GenerateRandomGroupElement returns a nonzero target-subgroup point") &&
        all_passed;

    ElGamalEnc::GroupElement group_element;
    group_element.group = enc.Group();
    group_element.value = EC_POINT_dup(random_group_element.get(), enc.Group());
    all_passed = ExpectTrue(
        enc.IsValidGroupElement(group_element),
        "GroupElement wraps a valid nonzero curve point") && all_passed;

    BnPtr seven = MakeScalar(7);
    BnPtr eleven = MakeScalar(11);
    BnPtr three = MakeScalar(3);
    BnPtr order_plus_seven(BN_dup(enc.Order()), BN_clear_free);
    if (order_plus_seven == nullptr ||
        BN_add(order_plus_seven.get(), order_plus_seven.get(), seven.get()) != 1)
    {
        throw std::runtime_error("test scalar addition failed");
    }

    PointPtr seven_point(enc.NewPoint(), EC_POINT_free);
    PointPtr eleven_point(enc.NewPoint(), EC_POINT_free);
    PointPtr reduced_point(enc.NewPoint(), EC_POINT_free);
    enc.EncodePlaintext(public_key, seven.get(), seven_point.get());
    enc.EncodePlaintext(public_key, eleven.get(), eleven_point.get());
    enc.EncodePlaintext(
        public_key,
        order_plus_seven.get(),
        reduced_point.get());
    all_passed = ExpectTrue(
        enc.PointsEqual(seven_point.get(), reduced_point.get()),
        "EncodePlaintext reduces scalars modulo the group order") && all_passed;

    BnPtr commitment_randomness = MakeScalar(19);
    ElGamalEnc::Commitment commitment;
    ElGamalEnc::Commitment repeated_commitment;
    enc.GenerateCommitmentWithRandomness(
        commitment_key,
        seven.get(),
        commitment_randomness.get(),
        commitment);
    enc.GenerateCommitmentWithRandomness(
        commitment_key,
        seven.get(),
        commitment_randomness.get(),
        repeated_commitment);
    all_passed = ExpectTrue(
        enc.IsValidCommitment(commitment) &&
            enc.PointsEqual(commitment.value, repeated_commitment.value),
        "GenerateCommitmentWithRandomness is valid and deterministic") &&
        all_passed;

    PointPtr expected_commitment(enc.NewPoint(), EC_POINT_free);
    PointPtr commitment_randomness_term(enc.NewPoint(), EC_POINT_free);
    const bool commitment_equation_ok =
        EC_POINT_mul(
            enc.Group(),
            expected_commitment.get(),
            nullptr,
            commitment_key.g,
            seven.get(),
            test_ctx.get()) == 1 &&
        EC_POINT_mul(
            enc.Group(),
            commitment_randomness_term.get(),
            nullptr,
            commitment_key.h,
            commitment_randomness.get(),
            test_ctx.get()) == 1 &&
        EC_POINT_add(
            enc.Group(),
            expected_commitment.get(),
            expected_commitment.get(),
            commitment_randomness_term.get(),
            test_ctx.get()) == 1;
    all_passed = ExpectTrue(
        commitment_equation_ok &&
            enc.PointsEqual(commitment.value, expected_commitment.get()),
        "commitment satisfies Com(m; rho) = m*g + rho*h") && all_passed;

    BnPtr generated_commitment_randomness(BN_new(), BN_clear_free);
    ElGamalEnc::Commitment randomized_commitment;
    enc.GenerateCommitment(
        commitment_key,
        eleven.get(),
        generated_commitment_randomness.get(),
        randomized_commitment);
    all_passed = ExpectTrue(
        enc.IsValidCommitment(randomized_commitment) &&
            !BN_is_zero(generated_commitment_randomness.get()) &&
            BN_cmp(generated_commitment_randomness.get(), enc.Order()) < 0,
        "GenerateCommitment generates and returns valid randomness") &&
        all_passed;

    BnPtr first_randomness(BN_new(), BN_clear_free);
    BnPtr second_randomness(BN_new(), BN_clear_free);
    ElGamalEnc::Ciphertext first_ciphertext;
    ElGamalEnc::Ciphertext second_ciphertext;
    enc.Encrypt(
        public_key,
        seven_point.get(),
        first_randomness.get(),
        first_ciphertext);
    enc.Encrypt(
        public_key,
        eleven_point.get(),
        second_randomness.get(),
        second_ciphertext);
    all_passed = ExpectTrue(
        enc.IsValidCiphertext(first_ciphertext) &&
            !BN_is_zero(first_randomness.get()),
        "Encrypt returns a valid ciphertext and randomness") && all_passed;

    PointPtr decrypted(enc.NewPoint(), EC_POINT_free);
    enc.Decrypt(public_key, secret_key, first_ciphertext, decrypted.get());
    all_passed = ExpectTrue(
        enc.PointsEqual(decrypted.get(), seven_point.get()),
        "encoded scalar encrypt/decrypt round trip") && all_passed;

    ElGamalEnc::Ciphertext repeated_ciphertext;
    enc.EncryptWithRandomness(
        public_key,
        seven_point.get(),
        first_randomness.get(),
        repeated_ciphertext);
    all_passed = ExpectTrue(
        CiphertextsEqual(enc, first_ciphertext, repeated_ciphertext),
        "EncryptWithRandomness is deterministic") && all_passed;

    PointPtr arbitrary_plaintext(enc.NewPoint(), EC_POINT_free);
    PointPtr arbitrary_decrypted(enc.NewPoint(), EC_POINT_free);
    BnPtr arbitrary_randomness(BN_new(), BN_clear_free);
    ElGamalEnc::Ciphertext arbitrary_ciphertext;
    enc.GenerateRandomGroupElement(arbitrary_plaintext.get());
    enc.Encrypt(
        public_key,
        arbitrary_plaintext.get(),
        arbitrary_randomness.get(),
        arbitrary_ciphertext);
    enc.Decrypt(
        public_key,
        secret_key,
        arbitrary_ciphertext,
        arbitrary_decrypted.get());
    all_passed = ExpectTrue(
        enc.PointsEqual(arbitrary_plaintext.get(), arbitrary_decrypted.get()),
        "ElGamal encrypts arbitrary EC_POINT plaintexts") && all_passed;

    PointPtr expected(enc.NewPoint(), EC_POINT_free);
    ElGamalEnc::Ciphertext added;
    enc.HomomorphicAdd(
        public_key,
        added,
        first_ciphertext,
        second_ciphertext);
    enc.Decrypt(public_key, secret_key, added, decrypted.get());
    const bool plaintext_add_ok = EC_POINT_add(
        enc.Group(),
        expected.get(),
        seven_point.get(),
        eleven_point.get(),
        test_ctx.get()) == 1;
    all_passed = ExpectTrue(
        plaintext_add_ok && enc.PointsEqual(decrypted.get(), expected.get()),
        "HomomorphicAdd adds EC_POINT plaintexts") && all_passed;

    ElGamalEnc::Ciphertext subtracted;
    enc.HomomorphicSubtract(
        public_key,
        subtracted,
        second_ciphertext,
        first_ciphertext);
    enc.Decrypt(public_key, secret_key, subtracted, decrypted.get());
    PointPtr negative_seven(
        EC_POINT_dup(seven_point.get(), enc.Group()),
        EC_POINT_free);
    const bool plaintext_subtract_ok =
        negative_seven != nullptr &&
        EC_POINT_invert(
            enc.Group(),
            negative_seven.get(),
            test_ctx.get()) == 1 &&
        EC_POINT_add(
            enc.Group(),
            expected.get(),
            eleven_point.get(),
            negative_seven.get(),
            test_ctx.get()) == 1;
    all_passed = ExpectTrue(
        plaintext_subtract_ok &&
            enc.PointsEqual(decrypted.get(), expected.get()),
        "HomomorphicSubtract subtracts EC_POINT plaintexts") && all_passed;

    ElGamalEnc::Ciphertext scaled;
    enc.ScalarMultiply(
        public_key,
        scaled,
        first_ciphertext,
        three.get());
    enc.Decrypt(public_key, secret_key, scaled, decrypted.get());
    const bool plaintext_scale_ok = EC_POINT_mul(
        enc.Group(),
        expected.get(),
        nullptr,
        seven_point.get(),
        three.get(),
        test_ctx.get()) == 1;
    all_passed = ExpectTrue(
        plaintext_scale_ok && enc.PointsEqual(decrypted.get(), expected.get()),
        "ScalarMultiply scales an EC_POINT plaintext") && all_passed;

    ElGamalEnc::PublicKey public_key_copy(public_key);
    ElGamalEnc::SecretKey secret_key_copy(secret_key);
    ElGamalEnc::CommitmentKey commitment_key_copy(commitment_key);
    ElGamalEnc::Commitment commitment_copy(commitment);
    ElGamalEnc::GroupElement group_element_copy(group_element);
    ElGamalEnc::Ciphertext ciphertext_copy(first_ciphertext);
    all_passed = ExpectTrue(
        enc.IsValidPublicKey(public_key_copy) &&
            BN_cmp(secret_key_copy.sk, secret_key.sk) == 0 &&
            enc.IsValidCommitmentKey(commitment_key_copy) &&
            enc.PointsEqual(commitment_copy.value, commitment.value) &&
            enc.IsValidGroupElement(group_element_copy) &&
            enc.PointsEqual(group_element_copy.value, group_element.value) &&
            CiphertextsEqual(enc, ciphertext_copy, first_ciphertext) &&
            public_key_copy.g != public_key.g &&
            public_key_copy.pk != public_key.pk &&
            secret_key_copy.sk != secret_key.sk &&
            commitment_key_copy.g != commitment_key.g &&
            commitment_copy.value != commitment.value &&
            group_element_copy.value != group_element.value &&
            ciphertext_copy.u != first_ciphertext.u,
        "key, commitment, group element, and ciphertext copy constructors are deep copies") &&
        all_passed;

    ElGamalEnc::PublicKey assigned_public_key;
    ElGamalEnc::SecretKey assigned_secret_key;
    ElGamalEnc::CommitmentKey assigned_commitment_key;
    ElGamalEnc::Commitment assigned_commitment;
    ElGamalEnc::GroupElement assigned_group_element;
    ElGamalEnc::Ciphertext assigned_ciphertext;
    assigned_public_key = public_key;
    assigned_secret_key = secret_key;
    assigned_commitment_key = commitment_key;
    assigned_commitment = commitment;
    assigned_group_element = group_element;
    assigned_ciphertext = first_ciphertext;
    all_passed = ExpectTrue(
        enc.IsValidPublicKey(assigned_public_key) &&
            BN_cmp(assigned_secret_key.sk, secret_key.sk) == 0 &&
            enc.IsValidCommitmentKey(assigned_commitment_key) &&
            enc.PointsEqual(assigned_commitment.value, commitment.value) &&
            enc.IsValidGroupElement(assigned_group_element) &&
            enc.PointsEqual(
                assigned_group_element.value,
                group_element.value) &&
            CiphertextsEqual(enc, assigned_ciphertext, first_ciphertext),
        "key, commitment, group element, and ciphertext copy assignments preserve values") &&
        all_passed;

    ElGamalEnc::PublicKey moved_public_key(std::move(public_key_copy));
    ElGamalEnc::SecretKey moved_secret_key(std::move(secret_key_copy));
    ElGamalEnc::CommitmentKey moved_commitment_key(
        std::move(commitment_key_copy));
    ElGamalEnc::Commitment moved_commitment(std::move(commitment_copy));
    ElGamalEnc::GroupElement moved_group_element(
        std::move(group_element_copy));
    ElGamalEnc::Ciphertext moved_ciphertext(std::move(ciphertext_copy));
    all_passed = ExpectTrue(
        enc.IsValidPublicKey(moved_public_key) &&
            moved_secret_key.sk != nullptr &&
            enc.IsValidCommitmentKey(moved_commitment_key) &&
            enc.IsValidCommitment(moved_commitment) &&
            enc.IsValidGroupElement(moved_group_element) &&
            enc.IsValidCiphertext(moved_ciphertext) &&
            public_key_copy.generator == nullptr &&
            public_key_copy.g == nullptr &&
            public_key_copy.pk == nullptr &&
            secret_key_copy.sk == nullptr &&
            commitment_key_copy.g == nullptr &&
            commitment_key_copy.h == nullptr &&
            commitment_copy.value == nullptr &&
            group_element_copy.value == nullptr &&
            ciphertext_copy.u == nullptr &&
            ciphertext_copy.e == nullptr,
        "key, commitment, group element, and ciphertext move constructors transfer ownership") &&
        all_passed;

    all_passed = ExpectTrue(
        !enc.IsValidPublicKey(ElGamalEnc::PublicKey{}) &&
            !enc.IsValidCommitmentKey(ElGamalEnc::CommitmentKey{}) &&
            !enc.IsValidCommitment(ElGamalEnc::Commitment{}) &&
            !enc.IsValidGroupElement(ElGamalEnc::GroupElement{}) &&
            !enc.IsValidCiphertext(ElGamalEnc::Ciphertext{}) &&
            !enc.PointsEqual(nullptr, seven_point.get()) &&
            !enc.PointsEqual(seven_point.get(), nullptr),
        "validation rejects empty objects and null points") && all_passed;

    all_passed = ExpectThrows(
        [&enc]() { enc.GenerateRandomScalar(nullptr); },
        "GenerateRandomScalar rejects a null output") && all_passed;
    all_passed = ExpectThrows(
        [&enc]() { enc.GenerateRandomGroupElement(nullptr); },
        "GenerateRandomGroupElement rejects a null output") && all_passed;
    all_passed = ExpectThrows(
        [&enc, &commitment_key, &commitment_randomness, &commitment]() {
            enc.GenerateCommitmentWithRandomness(
                commitment_key,
                nullptr,
                commitment_randomness.get(),
                commitment);
        },
        "commitment generation rejects a null plaintext scalar") && all_passed;
    all_passed = ExpectThrows(
        [&enc, &public_key, &first_randomness]() {
            ElGamalEnc::Ciphertext invalid_output;
            enc.EncryptWithRandomness(
                public_key,
                nullptr,
                first_randomness.get(),
                invalid_output);
        },
        "encryption rejects a null EC_POINT plaintext") && all_passed;

    if (!all_passed)
    {
        std::cerr << "ElGamalEnc full API test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "ElGamalEnc full API test passed" << std::endl;
    return EXIT_SUCCESS;
}
