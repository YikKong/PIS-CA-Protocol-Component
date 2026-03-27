/*
 * Camenisch-Shoup Encryption Core Implementation
 * Multi-key support with unified generator
 */

#pragma once

#include "cs_types.hpp"
#include <NTL/ZZ.h>
#include <openssl/sha.h>

namespace PIS_CA {

/**
 * @brief Core CS Encryption Operations
 */
class CSEncryption {
private:
    static constexpr ZZ ZERO(0);
    static constexpr ZZ ONE(1);
    static constexpr ZZ TWO(2);

public:
    /**
     * @brief 生成系统公共参数（包含两种批处理加密参数）
     * @param params 系统配置参数（包含 defaultS 第一种批处理和 keyCount 第二种批处理）
     * @return 生成的公共参数，包含统一生成元 g 和批处理配置
     */
    static CSPublicParams setup(const SystemParams& params);
    
    /**
     * @brief 生成第二种批处理加密所需的多个密钥对（共享生成元 g）
     * 生成的密钥对数量 = params.keyCount，对应密文 (u, e_1, e_2, ..., e_t) 中的 t
     * @param publicParams 公共参数（包含统一生成元 g）
     * @param params 系统配置（keyCount 决定第二种批处理的密文个数）
     * @return 密钥对向量 [(x1, pk1), (x2, pk2), ...]，长度为 keyCount
     */
    static std::vector<CSKeyPair> generateKeyPairs(
        const CSPublicParams& publicParams, 
        const SystemParams& params
    );
    
    /**
     * @brief Generate commitment key with configurable dimension
     * @param publicParams Public parameters
     * @param params System configuration (determines commit dimension)
     * @return Commitment key with g[0..dimension-1] and h
     */
    static CSCommitKey generateCommitKey(
        const CSPublicParams& publicParams,
        const SystemParams& params
    );
    
    /**
     * @brief 加密明文（支持两种批处理加密方式）
     * 
     * 第一种批处理：单个密文 ei 编码多个明文（message 长度为 defaultS）
     * 第二种批处理：多个 ei 共享同一个 u（通过 generateKeyPairs 生成多对密钥）
     * 
     * 当两种批处理同时使用时：
     * - 总加密容量 = defaultS × keyCount 个明文
     * - 密文形式：(u, e_1, e_2, ..., e_keyCount)
     * - 每个 ei 编码 defaultS 个明文
     * 
     * @param publicParams 公共参数
     * @param keyPair 用于加密的密钥对（第二种批处理中每个 ei 使用不同 keyPair）
     * @param message 明文向量（长度为 defaultS，第一种批处理）
     * @param randomness 随机数（为 nullptr 时自动生成，第二种批处理中所有 ei 共享同一 randomness）
     * @return 密文 c = (u, e)，其中 e = pk^r * T^encodedMessage
     */
    static CSCiphertext encrypt(
        const CSPublicParams& publicParams,
        const CSKeyPair& keyPair,
        const Plaintext& message,
        const ZZ* randomness = nullptr
    );
    
    /**
     * @brief 使用外部随机数加密（支持两种批处理加密）
     * 
     * 第二种批处理中，调用方需确保所有 ei 使用相同的 randomness，
     * 以保证密文 (u, e_1, ..., e_t) 共享同一个 u = g^r
     * 
     * @param publicParams 公共参数
     * @param keyPair 用于加密的密钥对
     * @param message 明文向量（长度为 defaultS）
     * @param randomness 外部提供的随机数 r
     * @return 密文 c = (u, e)
     */
    static CSCiphertext encryptWithRandom(
        const CSPublicParams& publicParams,
        const CSKeyPair& keyPair,
        const Plaintext& message,
        const ZZ& randomness
    );
    
    /**
     * @brief 解密密文（支持两种批处理加密方式）
     * 
     * 第一种批处理：从单个 ei 解码 defaultS 个明文
     * 第二种批处理：需对每个 ei 单独调用 decrypt，使用对应密钥对的 secretKey
     * 
     * @param publicParams 公共参数
     * @param secretKey 密钥对的私钥 x
     * @param ciphertext 密文 (u, e)
     * @return 解密后的明文向量（长度为 defaultS）
     */
    static Plaintext decrypt(
        const CSPublicParams& publicParams,
        const ZZ& secretKey,
        const CSCiphertext& ciphertext
    );
    
    /**
     * @brief Homomorphic addition: c1 + c2
     */
    static CSCiphertext homomorphicAdd(
        const CSPublicParams& publicParams,
        const CSCiphertext& c1,
        const CSCiphertext& c2
    );
    
    /**
     * @brief Homomorphic subtraction: c1 - c2
     */
    static CSCiphertext homomorphicSub(
        const CSPublicParams& publicParams,
        const CSCiphertext& c1,
        const CSCiphertext& c2
    );
    
    /**
     * @brief Scalar multiplication: k * c
     */
    static CSCiphertext scalarMultiply(
        const CSPublicParams& publicParams,
        const CSCiphertext& c,
        const ZZ& scalar
    );

private:
    /**
     * @brief Compute discrete logarithm for decryption
     * L(m) = (m - 1) / N
     */
    static ZZ computeL(const CSPublicParams& publicParams, const ZZ& m);
    
    /**
     * @brief Extended discrete log for higher powers
     * Decodes (1+N)^m to recover m
     */
    static ZZ decodeDLog(const CSPublicParams& publicParams, const ZZ& value, uint32_t zeta);
    
    /**
     * @brief 将明文向量编码为单个大整数（第一种批处理编码）
     * 
     * 将 defaultS 个明文编码为单个整数：
     * m = m1 + m2*(2^B) + m3*(2^B)^2 + ... + m_defaultS*(2^B)^(defaultS-1)
     * 
     * 编码后的大整数可通过 (1+N)^m 嵌入密文
     * 
     * @param publicParams 公共参数（包含 messageRangeBase = 2^B）
     * @param message 明文向量（长度为 defaultS）
     * @return 编码后的大整数
     */
    static ZZ encodeMessageVector(
        const CSPublicParams& publicParams,
        const Plaintext& message
    );
    
    /**
     * @brief 将单个大整数解码为明文向量（第一种批处理解码）
     * 
     * 逆向编码过程，从编码值恢复 defaultS 个明文：
     * mi = (encoded / (2^B)^i) mod (2^B)
     * 
     * @param publicParams 公共参数
     * @param encoded 编码后的大整数
     * @param dimension 明文向量维度（即 defaultS）
     * @return 解码后的明文向量
     */
    static Plaintext decodeMessage(
        const CSPublicParams& publicParams,
        const ZZ& encoded,
        uint32_t dimension
    );
    
    /**
     * @brief Generate random ZZ
     */
    static ZZ generateRandom(const ZZ& modulus);
    
    /**
     * @brief Compute 2^B powers for encoding
     */
    static void precomputePowerTwoB(CSPublicParams& publicParams, uint32_t maxDimension);
};

} // namespace PIS_CA
