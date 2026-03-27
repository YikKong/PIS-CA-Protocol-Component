/*
 * PIS-CA Protocol Component - Refactored Architecture
 * Camenisch-Shoup Encryption System with Multi-Key Support
 */

#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <openssl/sha.h>
#include <NTL/ZZ.h>

using namespace NTL;

namespace PIS_CA {

/**
 * @brief System configuration constants - now runtime configurable
 */
struct SystemParams {
    // Security parameters (runtime configurable with defaults)
    uint32_t primeBits;       // RSA模数 N = p·q 中 p 和 q 的长度
    uint32_t zeta;            // n^s parameter for CS (default: 2)
    uint32_t defaultS;        // 第一种批处理：单个密文里可容纳的明文个数
    uint32_t bBits;           // 密文批处理加密时，明文子空间长度
    static constexpr uint32_t HASH_BYTES = 32;  // SHA256 output size
    
    // Configurable parameters (set at initialization)
    uint32_t keyCount;        // 第二种批处理：多个密文ei共享同一个u的密文个数
    uint32_t commitDimension; // Dimension of commitment key vectors
    
    SystemParams(
        uint32_t keys = 1, 
        uint32_t commitDim = 4,
        uint32_t pBits = 768,
        uint32_t z = 2,
        uint32_t s = 4,
        uint32_t b = 768
    ) : keyCount(keys), 
        commitDimension(commitDim),
        primeBits(pBits),
        zeta(z),
        defaultS(s),
        bBits(b) {}
        
    // Backward compatibility accessors
    static uint32_t PRIME_BITS(const SystemParams& p) { return p.primeBits; }
    static uint32_t ZETA(const SystemParams& p) { return p.zeta; }
    static uint32_t DEFAULT_S(const SystemParams& p) { return p.defaultS; }
    static uint32_t B_BITS(const SystemParams& p) { return p.bBits; }
};

/**
 * @brief Camenisch-Shoup Public Parameters (shared across all keys)
 */
struct CSPublicParams {
    ZZ rsaModulus;              // RSA modulus N = p * q
    ZZ rsaSubgroupOrder;        // (p-1)/2 * (q-1)/2 = N'
    ZZ nToZetaPlus1;            // N^(zeta+1) - main modulus for encryption
    ZZ sharedGenerator;         // Shared generator g (unified across all key pairs)
    ZZ T;        // (1 + N) mod N^(zeta+1), 用于消息编码
    ZZ messageRangeBase;        // 2^B for message encoding
    
    // Runtime configurable parameters (stored for reference)
    uint32_t messageVectorDimension;  // Number of messages per encryption (s)
    uint32_t messageBitLength;  // Message range parameter (B bits)
    
    // Pre-computed values for optimization
    std::vector<ZZ> powersOfRangeBase; // Powers of 2^B for message encoding
};

/**
 * @brief 第二种批处理加密的密钥对集合 (e_1, e_2, ..., e_t 共享同一个 u)
 * 每个密钥对对应一个 ei 密文分量
 */
struct CSKeyPair {
    ZZ secretKey;           // Secret key x
    ZZ publicKey;           // Public key = g^x mod N^(zeta+1)
    uint32_t keyIndex;      // Key index in the set
    
    CSKeyPair() : keyIndex(0) {}
    explicit CSKeyPair(uint32_t idx) : keyIndex(idx) {}
};

/**
 * @brief Commitment Key with configurable dimension
 * Structure: generators = [g1, g2, ..., gn] where n = commitDimension
 *             randomnessGenerator = h for randomness
 */
struct CSCommitKey {
    std::vector<ZZ> generators;  // Vector of commitment generators [g1, g2, ..., g_dim]
    ZZ randomnessGenerator;      // Randomness generator h
    
    explicit CSCommitKey(uint32_t dimension = 4) {
        generators.reserve(dimension);
    }
    
    uint32_t getDimension() const { return static_cast<uint32_t>(generators.size()); }
};

/**
 * @brief Camenisch-Shoup Ciphertext (single key)
 * c = (randomnessComponent, encryptedMessage) 
 * where randomnessComponent = g^r, encryptedMessage = pk^r * (1+N)^m
 */
struct CSCiphertext {
    ZZ randomnessComponent;    // u = g^r mod N^(zeta+1)
    ZZ encryptedMessage;       // e = pk^r * (1+N)^m mod N^(zeta+1)
    
    CSCiphertext() : randomnessComponent(0), encryptedMessage(0) {}
    CSCiphertext(const ZZ& u_, const ZZ& e_) : randomnessComponent(u_), encryptedMessage(e_) {}
};

/**
 * @brief Multi-Key Camenisch-Shoup Ciphertext
 * c = (randomnessComponent, e_1, e_2, ..., e_t) where t = number of key pairs
 * Each e_j encrypts a message vector of dimension messageVectorDimension
 * Total messages: messageVectorDimension × t
 */
struct CSMultiKeyCiphertext {
    ZZ randomnessComponent;           // Shared randomness component u
    std::vector<ZZ> encryptedMessages;  // e_1, e_2, ..., e_t for each key pair
    uint32_t messageVectorDimension;    // Number of messages per key (for reference)
    
    CSMultiKeyCiphertext() : randomnessComponent(0), messageVectorDimension(0) {}
    
    explicit CSMultiKeyCiphertext(uint32_t keyCount, uint32_t msgDim = 4) 
        : randomnessComponent(0), encryptedMessages(keyCount), messageVectorDimension(msgDim) {}
    
    size_t getKeyCount() const { return encryptedMessages.size(); }
    
    CSCiphertext getSingleCiphertext(size_t index) const {
        if (index >= encryptedMessages.size()) {
            throw std::out_of_range("Ciphertext index out of range");
        }
        return CSCiphertext(randomnessComponent, encryptedMessages[index]);
    }
};

/**
 * @brief Pedersen-style Commitment on CS group
 * commitmentValue = randomnessGenerator^randomness * prod(generators[i]^messages[i]) mod N^2
 */
struct CSCommitment {
    ZZ commitmentValue;     // Commitment value (Com)
    ZZ randomness;          // Randomness used (optional storage)
    
    CSCommitment() : commitmentValue(0), randomness(0) {}
    explicit CSCommitment(const ZZ& value) : commitmentValue(value), randomness(0) {}
};

/**
 * @brief 明文向量类型（明文消息集合）
 */
using Plaintext = std::vector<ZZ>;

} // namespace PIS_CA
