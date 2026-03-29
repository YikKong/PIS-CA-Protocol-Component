#pragma once

#include "../core/params.hpp"

namespace CS {

class VectorCommitmentScheme {
public:
    // Setup commitment key
    static CommitKey setup(const PublicParams& pp, uint32_t vectorDimension);
    
    // Commit to a vector
    static VectorCommitment commit(
        const PublicParams& pp,
        const CommitKey& ck,
        const Plaintext& vector,
        const ZZ& randomness
    );
    
    // Verify commitment opening
    static bool verify(
        const PublicParams& pp,
        const CommitKey& ck,
        const VectorCommitment& comm,
        const Plaintext& vector,
        const ZZ& randomness
    );
    
    // Homomorphic operations
    static VectorCommitment add(
        const PublicParams& pp,
        const CommitKey& ck,
        const VectorCommitment& c1,
        const VectorCommitment& c2
    );
    
    static VectorCommitment scalarMul(
        const PublicParams& pp,
        const CommitKey& ck,
        const VectorCommitment& comm,
        const ZZ& scalar
    );
    
    // Fold commitments (merge multiple into one)
    static VectorCommitment fold(
        const PublicParams& pp,
        const std::vector<CommitKey>& cks,
        const std::vector<VectorCommitment>& comms,
        const std::vector<ZZ>& weights
    );

private:
    // Inner product of vector with generators
    static ZZ innerProductCommit(
        const PublicParams& pp,
        const CommitKey& ck,
        const Plaintext& vector
    );
};

} // namespace CS
