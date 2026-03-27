/*
 * CS Context - Unified management of keys and parameters
 */

#pragma once

#include "cs_types.hpp"
#include "cs_encryption.hpp"
#include "cs_commitment.hpp"

namespace PIS_CA {

/**
 * @brief Unified context for CS operations
 * Manages public parameters, multiple key pairs, and commitment keys
 */
class CSContext {
private:
    CSPublicParams publicParams_;
    SystemParams systemParams_;
    std::vector<CSKeyPair> keyPairs_;
    CSCommitKey commitKey_;
    bool initialized_;
    
public:
    /**
     * @brief Create empty context (must call initialize)
     */
    CSContext();
    
    /**
     * @brief Initialize with specific parameters
     * @param params System parameters (key count, commit dimension)
     */
    explicit CSContext(const SystemParams& params);
    
    /**
     * @brief Initialize the context
     * Generates all parameters, keys, and commitment keys
     */
    void initialize(const SystemParams& params);
    
    /**
     * @brief Check if context is initialized
     */
    bool isInitialized() const { return initialized_; }
    
    // ===== Parameter Access =====
    
    const CSPublicParams& getPublicParams() const { return publicParams_; }
    const SystemParams& getSystemParams() const { return systemParams_; }
    
    // ===== Key Pair Management =====
    
    /**
     * @brief Get number of key pairs
     */
    size_t getKeyCount() const { return keyPairs_.size(); }
    
    /**
     * @brief Get key pair by index
     */
    const CSKeyPair& getKeyPair(size_t index) const;
    
    /**
     * @brief Get all key pairs
     */
    const std::vector<CSKeyPair>& getAllKeyPairs() const { return keyPairs_; }
    
    /**
     * @brief Add a new key pair to the set
     */
    void addKeyPair();
    
    // ===== Commitment Key =====
    
    const CSCommitKey& getCommitKey() const { return commitKey_; }
    
    /**
     * @brief Extend commitment key dimension
     */
    void extendCommitDimension(uint32_t newDimension);
    
    // ===== Encryption Operations =====
    
    /**
     * @brief Encrypt using specific key pair
     */
    CSCiphertext encrypt(
        size_t keyIndex,
        const Plaintext& message,
        const ZZ* randomness = nullptr
    ) const;
    
    /**
     * @brief Decrypt using specific key pair
     */
    Plaintext decrypt(size_t keyIndex, const CSCiphertext& ciphertext) const;
    
    /**
     * @brief Homomorphic addition
     */
    CSCiphertext homoAdd(const CSCiphertext& c1, const CSCiphertext& c2) const;
    
    /**
     * @brief Homomorphic subtraction
     */
    CSCiphertext homoSub(const CSCiphertext& c1, const CSCiphertext& c2) const;
    
    /**
     * @brief Scalar multiplication
     */
    CSCiphertext scalarMul(const CSCiphertext& c, const ZZ& scalar) const;
    
    // ===== Commitment Operations =====
    
    /**
     * @brief Create commitment to message vector
     */
    CSCommitment commit(
        const Plaintext& messages,
        const ZZ* randomness = nullptr
    ) const;
    
    /**
     * @brief Verify commitment
     */
    bool verifyCommitment(
        const CSCommitment& commitment,
        const Plaintext& messages,
        const ZZ& randomness
    ) const;
    
    /**
     * @brief Commitment homomorphic add
     */
    CSCommitment commitAdd(const CSCommitment& c1, const CSCommitment& c2) const;
    
    /**
     * @brief Commitment scalar multiply
     */
    CSCommitment commitScalarMul(const CSCommitment& c, const ZZ& scalar) const;
};

} // namespace PIS_CA
