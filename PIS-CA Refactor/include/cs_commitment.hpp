/*
 * Pedersen Commitment on Camenisch-Shoup Group
 * Multi-dimensional commitment support
 */

#pragma once

#include "cs_types.hpp"

namespace PIS_CA {

/**
 * @brief Commitment System on CS Group
 * commitment = randomnessGenerator^randomness * prod(generators[i]^messages[i]) mod N^2
 */
class CSCommitmentScheme {
public:
    /**
     * @brief Generate commitment to message vector
     * @param publicParams Public parameters
     * @param commitKey Commitment key (contains g[0..dim-1] and h)
     * @param messages Message vector [m1, m2, ..., md] (d <= commitDimension)
     * @param randomness Randomness (if null, generated internally)
     * @return Commitment = h^r * prod(gi^mi)
     */
    static CSCommitment commit(
        const CSPublicParams& publicParams,
        const CSCommitKey& commitKey,
        const Plaintext& messages,
        const ZZ* randomness = nullptr
    );
    
    /**
     * @brief Generate commitment with specific randomness
     */
    static CSCommitment commitWithRandom(
        const CSPublicParams& publicParams,
        const CSCommitKey& commitKey,
        const Plaintext& messages,
        const ZZ& randomness
    );
    
    /**
     * @brief Verify commitment (for testing/debugging)
     * @param publicParams Public parameters
     * @param commitKey Commitment key
     * @param commitment Commitment to verify
     * @param messages Expected messages
     * @param randomness Expected randomness
     * @return true if commitment is valid
     */
    static bool verify(
        const CSPublicParams& publicParams,
        const CSCommitKey& commitKey,
        const CSCommitment& commitment,
        const Plaintext& messages,
        const ZZ& randomness
    );
    
    /**
     * @brief Homomorphic commitment addition
     * Com1 * Com2 commits to (m1+m2, ..., mn+mn) with (r1+r2)
     */
    static CSCommitment add(
        const CSPublicParams& publicParams,
        const CSCommitment& c1,
        const CSCommitment& c2
    );
    
    /**
     * @brief Scalar multiplication of commitment
     * Com^k commits to (k*m1, ..., k*mn) with (k*r)
     */
    static CSCommitment scalarMul(
        const CSPublicParams& publicParams,
        const CSCommitment& commitment,
        const ZZ& scalar
    );
    
    /**
     * @brief Generate commitment to single value using first generator
     * Convenience method for single-value commitments
     */
    static CSCommitment commitSingle(
        const CSPublicParams& publicParams,
        const CSCommitKey& commitKey,
        const ZZ& message,
        const ZZ* randomness = nullptr
    );

private:
    /**
     * @brief Internal commitment computation
     * result = h^r * g[0]^m[0] * g[1]^m[1] * ... mod N^2
     */
    static ZZ computeCommitment(
        const CSPublicParams& publicParams,
        const CSCommitKey& commitKey,
        const Plaintext& messages,
        const ZZ& randomness
    );
};

/**
 * @brief Utilities for commitment operations
 */
class CSCommitmentUtils {
public:
    /**
     * @brief Create commitment key from dimension
     * Factory method for convenience
     */
    static CSCommitKey createCommitKey(
        const CSPublicParams& publicParams,
        uint32_t dimension
    );
    
    /**
     * @brief Extend existing commitment key to new dimension
     */
    static void extendDimension(
        CSPublicParams& publicParams,
        CSCommitKey& commitKey,
        uint32_t newDimension,
        uint32_t primeBits
    );
};

} // namespace PIS_CA
