/*
 * Utility Functions Implementation
 */

#include "../include/cs_utils.hpp"
#include <openssl/sha.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace PIS_CA {

// StringUtils Implementation

ZZ StringUtils::stringToZZ(const std::string& str) {
    ZZ number = conv<ZZ>(str[0]) - 48;
    long len = str.length();
    for (long i = 1; i < len; i++) {
        number *= 10;
        number += conv<ZZ>(str[i]) - 48;
    }
    return number;
}

std::string StringUtils::ZZToString(const ZZ& num) {
    std::vector<char> str;
    long t;
    ZZ temp = num;
    
    while (temp != 0) {
        conv(t, temp % 10);
        char c = static_cast<char>(t) + '0';
        str.push_back(c);
        temp /= 10;
    }
    
    std::reverse(str.begin(), str.end());
    return std::string(str.begin(), str.end());
}

std::string StringUtils::bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<uint8_t> StringUtils::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// HashUtils Implementation

void HashUtils::sha256(const std::string& input, uint8_t output[HASH_BYTES]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input.data(), input.size());
    SHA256_Final(output, &ctx);
}

void HashUtils::sha256(const uint8_t* input, size_t len, uint8_t output[HASH_BYTES]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, len);
    SHA256_Final(output, &ctx);
}

ZZ HashUtils::hashToZZ(const ZZ& input) {
    size_t len = NumBytes(input);
    std::vector<uint8_t> buf(len);
    BytesFromZZ(buf.data(), input, len);
    
    uint8_t hash[HASH_BYTES];
    sha256(buf.data(), len, hash);
    
    return ZZFromBytes(hash, HASH_BYTES);
}

ZZ HashUtils::hashToZZ(const std::string& input) {
    uint8_t hash[HASH_BYTES];
    sha256(input, hash);
    return ZZFromBytes(hash, HASH_BYTES);
}

ZZ HashUtils::generateChallenge(const ZZ& commitment) {
    return hashToZZ(commitment);
}

ZZ HashUtils::generateChallenge(const std::vector<ZZ>& values) {
    std::string input;
    for (const auto& val : values) {
        input += StringUtils::ZZToString(val);
    }
    return hashToZZ(input);
}

// MathUtils Implementation

ZZ MathUtils::extendedEuclideanGcd(const ZZ& a, const ZZ& b, ZZ& x, ZZ& y) {
    if (b == 0) {
        x = ZZ(1);
        y = ZZ(0);
        return a;
    }
    
    ZZ x1, y1;
    ZZ g = extendedEuclideanGcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

ZZ MathUtils::modInv(const ZZ& a, const ZZ& m) {
    return InvMod(a, m);
}

void MathUtils::generateSafePrime(ZZ& p, long bits) {
    GenGermainPrime(p, bits);
}

bool MathUtils::isQuadraticResidue(const ZZ& a, const ZZ& n) {
    return PowerMod(a, (n - 1) / 2, n) == 1;
}

ZZ MathUtils::randomInMultGroup(const ZZ& n) {
    ZZ r;
    while (true) {
        RandomBnd(r, n);
        if (GCD(r, n) == 1) {
            return r;
        }
    }
}

ZZ MathUtils::randomBits(uint32_t bitLength) {
    ZZ r;
    RandomBits(r, bitLength);
    return r;
}

// SerializationUtils Implementation

std::vector<uint8_t> SerializationUtils::serializeZZ(const ZZ& value) {
    size_t len = NumBytes(value);
    std::vector<uint8_t> result(len);
    BytesFromZZ(result.data(), value, len);
    return result;
}

ZZ SerializationUtils::deserializeZZ(const uint8_t* data, size_t len) {
    return ZZFromBytes(data, static_cast<long>(len));
}

std::vector<uint8_t> SerializationUtils::serializeCiphertext(const CSCiphertext& ct) {
    size_t u_len = NumBytes(ct.u);
    size_t e_len = NumBytes(ct.e);
    
    std::vector<uint8_t> result(8 + u_len + e_len);
    
    // Write lengths (4 bytes each)
    result[0] = (u_len >> 24) & 0xFF;
    result[1] = (u_len >> 16) & 0xFF;
    result[2] = (u_len >> 8) & 0xFF;
    result[3] = u_len & 0xFF;
    
    result[4] = (e_len >> 24) & 0xFF;
    result[5] = (e_len >> 16) & 0xFF;
    result[6] = (e_len >> 8) & 0xFF;
    result[7] = e_len & 0xFF;
    
    // Write data
    BytesFromZZ(result.data() + 8, ct.u, u_len);
    BytesFromZZ(result.data() + 8 + u_len, ct.e, e_len);
    
    return result;
}

CSCiphertext SerializationUtils::deserializeCiphertext(const uint8_t* data, size_t len) {
    if (len < 8) {
        return CSCiphertext();
    }
    
    size_t u_len = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    size_t e_len = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    
    CSCiphertext ct;
    ct.u = ZZFromBytes(data + 8, u_len);
    ct.e = ZZFromBytes(data + 8 + u_len, e_len);
    
    return ct;
}

std::vector<uint8_t> SerializationUtils::serializeCommitment(const CSCommitment& com) {
    size_t len = NumBytes(com.com);
    std::vector<uint8_t> result(len);
    BytesFromZZ(result.data(), com.com, len);
    return result;
}

CSCommitment SerializationUtils::deserializeCommitment(const uint8_t* data, size_t len) {
    CSCommitment com;
    com.com = ZZFromBytes(data, len);
    return com;
}

} // namespace PIS_CA
