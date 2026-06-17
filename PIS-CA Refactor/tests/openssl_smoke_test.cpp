#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace
{
std::string ToHex(const unsigned char* data, std::size_t size)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i)
    {
        out << std::setw(2) << static_cast<int>(data[i]);
    }
    return out.str();
}

bool TestSha256()
{
    const std::string message = "abc";
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};

    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1 ||
        SHA256_Update(&ctx, message.data(), message.size()) != 1 ||
        SHA256_Final(digest.data(), &ctx) != 1)
    {
        std::cerr << "[FAIL] SHA256 API call failed" << std::endl;
        return false;
    }

    const std::string expected =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    const std::string actual = ToHex(digest.data(), digest.size());

    if (actual != expected)
    {
        std::cerr << "[FAIL] SHA256 digest mismatch" << std::endl;
        std::cerr << "  expected: " << expected << std::endl;
        std::cerr << "  actual:   " << actual << std::endl;
        return false;
    }

    std::cout << "[PASS] SHA256 known-answer test" << std::endl;
    return true;
}

bool TestRandomBytes()
{
    std::array<unsigned char, 32> bytes{};

    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
    {
        std::cerr << "[FAIL] RAND_bytes failed" << std::endl;
        return false;
    }

    bool any_nonzero = false;
    for (const unsigned char byte : bytes)
    {
        any_nonzero = any_nonzero || byte != 0;
    }

    if (!any_nonzero)
    {
        std::cerr << "[FAIL] RAND_bytes returned all zeros" << std::endl;
        return false;
    }

    std::cout << "[PASS] RAND_bytes generated non-zero random data" << std::endl;
    return true;
}

bool TestBigNumberModExp()
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* base = BN_new();
    BIGNUM* exponent = BN_new();
    BIGNUM* modulus = BN_new();
    BIGNUM* result = BN_new();

    if (ctx == nullptr || base == nullptr || exponent == nullptr || modulus == nullptr || result == nullptr)
    {
        std::cerr << "[FAIL] BIGNUM allocation failed" << std::endl;
        BN_free(result);
        BN_free(modulus);
        BN_free(exponent);
        BN_free(base);
        BN_CTX_free(ctx);
        return false;
    }

    BN_set_word(base, 5);
    BN_set_word(exponent, 117);
    BN_set_word(modulus, 19);

    const bool ok =
        BN_mod_exp(result, base, exponent, modulus, ctx) == 1 &&
        BN_get_word(result) == 1;

    BN_free(result);
    BN_free(modulus);
    BN_free(exponent);
    BN_free(base);
    BN_CTX_free(ctx);

    if (!ok)
    {
        std::cerr << "[FAIL] BN_mod_exp result mismatch" << std::endl;
        return false;
    }

    std::cout << "[PASS] BN_mod_exp modular exponentiation" << std::endl;
    return true;
}

bool TestECGroupPrecomputeMult()
{
#ifdef OPENSSL_NO_EC
    std::cerr << "[FAIL] OpenSSL was built without EC support" << std::endl;
    return false;
#else
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if (ctx == nullptr || group == nullptr)
    {
        std::cerr << "[FAIL] EC_GROUP or BN_CTX allocation failed" << std::endl;
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        return false;
    }

    const int ret = EC_GROUP_precompute_mult(group, ctx);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    if (ret != 1)
    {
        std::cerr << "[FAIL] EC_GROUP_precompute_mult call failed" << std::endl;
        return false;
    }

    std::cout << "[PASS] EC_GROUP_precompute_mult is available and callable" << std::endl;
    return true;
#endif
}
}

int main()
{
    std::cout << "OpenSSL smoke test" << std::endl;
    std::cout << "Compile-time OpenSSL version: "
              << OPENSSL_VERSION_TEXT << std::endl;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    std::cout << "Runtime OpenSSL version: "
              << OpenSSL_version(OPENSSL_VERSION) << std::endl;
#endif

    bool all_passed = true;
    all_passed = TestSha256() && all_passed;
    all_passed = TestRandomBytes() && all_passed;
    all_passed = TestBigNumberModExp() && all_passed;
    all_passed = TestECGroupPrecomputeMult() && all_passed;

    if (!all_passed)
    {
        std::cerr << "OpenSSL smoke test failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "OpenSSL smoke test passed" << std::endl;
    return EXIT_SUCCESS;
}

// .\build\openssl_smoke_test.exe