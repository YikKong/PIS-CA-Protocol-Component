#pragma once

#include "params.hpp"
#include <openssl/sha.h>

namespace CS {

class Encryption {
public:
    // Setup: generate system parameters
    static void setup(PublicParams& pp, const SystemParams& sp);
    
    // Key generation
    static KeyPair generateKeyPair(const PublicParams& pp, const SystemParams& sp);
    
    // Single message encryption
    static void encrypt(
        const PublicParams& pp,
        const KeyPair& kp,
        const ZZ& message,
        SingleCiphertext& ct,
        ZZ& randomness
    );
    
    // Single message decryption
    static ZZ decrypt(
        const PublicParams& pp,
        const KeyPair& kp,
        const SingleCiphertext& ct
    );
    
    // Batch encryption (Type 1: multiple messages with same randomness)
    static void encryptBatchSameRandom(
        const PublicParams& pp,
        const KeyPair& kp,
        const Plaintext& messages,
        BatchCiphertext& ct,
        ZZ& randomness
    );
    
    // Batch decryption (Type 1)
    static Plaintext decryptBatchSameRandom(
        const PublicParams& pp,
        const KeyPair& kp,
        const BatchCiphertext& ct
    );
    
    // Batch encryption (Type 2: multiple messages with different randomness)
    static void encryptBatchDifferentRandom(
        const PublicParams& pp,
        const KeyPair& kp,
        const Plaintext& messages,
        BatchCiphertext& ct,
        std::vector<ZZ>& randomness
    );
    
    // Batch decryption (Type 2)
    static Plaintext decryptBatchDifferentRandom(
        const PublicParams& pp,
        const KeyPair& kp,
        const BatchCiphertext& ct,
        const std::vector<ZZ>& randomness
    );
    
    // Homomorphic operations
    static SingleCiphertext homomorphicAdd(
        const PublicParams& pp,
        const SingleCiphertext& c1,
        const SingleCiphertext& c2
    );
    
    static SingleCiphertext homomorphicSub(
        const PublicParams& pp,
        const SingleCiphertext& c1,
        const SingleCiphertext& c2
    );
    
    static SingleCiphertext scalarMultiply(
        const PublicParams& pp,
        const SingleCiphertext& ct,
        const ZZ& scalar
    );

private:
    // Utility functions
    static ZZ computeL(const PublicParams& pp, const ZZ& value);
    static ZZ encodeBatch(const PublicParams& pp, const Plaintext& messages);
    static Plaintext decodeBatch(const PublicParams& pp, const ZZ& encoded, uint32_t count);
    static ZZ hashToZZ(const uint8_t* data, size_t len);
};

} // namespace CS
