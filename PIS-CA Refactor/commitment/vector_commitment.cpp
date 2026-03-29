#include "vector_commitment.hpp"
#include <NTL/ZZ.h>

using namespace NTL;

namespace CS {

CommitKey VectorCommitmentScheme::setup(const PublicParams& pp, uint32_t vectorDimension) {
    CommitKey ck;
    ck.g.resize(vectorDimension);
    
    // Generate random generators for each dimension
    for (uint32_t i = 0; i < vectorDimension; i++) {
        ck.g[i] = RandomBnd(pp.N);
        // Ensure generator is valid
        while (ck.g[i] == 0 || GCD(ck.g[i], pp.N) != 1) {
            ck.g[i] = RandomBnd(pp.N);
        }
    }
    
    // Generator for randomness
    ck.h = RandomBnd(pp.N);
    while (ck.h == 0 || GCD(ck.h, pp.N) != 1) {
        ck.h = RandomBnd(pp.N);
    }
    
    return ck;
}

ZZ VectorCommitmentScheme::innerProductCommit(
    const PublicParams& pp,
    const CommitKey& ck,
    const Plaintext& vector
) {
    ZZ result = ZZ(1);
    size_t minDim = min(vector.size(), ck.g.size());
    
    for (size_t i = 0; i < minDim; i++) {
        // g_i^{m_i} mod N^2
        ZZ term = PowerMod(ck.g[i], vector[i], pp.N * pp.N);
        result = MulMod(result, term, pp.N * pp.N);
    }
    
    return result;
}

VectorCommitment VectorCommitmentScheme::commit(
    const PublicParams& pp,
    const CommitKey& ck,
    const Plaintext& vector,
    const ZZ& randomness
) {
    VectorCommitment comm;
    
    // c = g_1^{m_1} * g_2^{m_2} * ... * g_n^{m_n} * h^r mod N
    ZZ innerProd = innerProductCommit(pp, ck, vector);
    ZZ h_r = PowerMod(ck.h, randomness, pp.N * pp.N);
    
    comm.value = MulMod(innerProd, h_r, pp.N * pp.N);
    comm.randomness = randomness;
    
    return comm;
}

bool VectorCommitmentScheme::verify(
    const PublicParams& pp,
    const CommitKey& ck,
    const VectorCommitment& comm,
    const Plaintext& vector,
    const ZZ& randomness
) {
    // Recompute commitment
    VectorCommitment recomputed = commit(pp, ck, vector, randomness);
    
    // Compare values
    return (comm.value == recomputed.value);
}

VectorCommitment VectorCommitmentScheme::add(
    const PublicParams& pp,
    const CommitKey& ck,
    const VectorCommitment& c1,
    const VectorCommitment& c2
) {
    VectorCommitment result;
    
    // c_add = c1 * c2 mod N^2
    result.value = MulMod(c1.value, c2.value, pp.N * pp.N);
    
    // r_add = r1 + r2
    result.randomness = c1.randomness + c2.randomness;
    
    return result;
}

VectorCommitment VectorCommitmentScheme::scalarMul(
    const PublicParams& pp,
    const CommitKey& ck,
    const VectorCommitment& comm,
    const ZZ& scalar
) {
    VectorCommitment result;
    
    // c_scalar = c^scalar mod N^2
    result.value = PowerMod(comm.value, scalar, pp.N * pp.N);
    
    // r_scalar = r * scalar
    result.randomness = comm.randomness * scalar;
    
    return result;
}

VectorCommitment VectorCommitmentScheme::fold(
    const PublicParams& pp,
    const std::vector<CommitKey>& cks,
    const std::vector<VectorCommitment>& comms,
    const std::vector<ZZ>& weights
) {
    assert(cks.size() == comms.size());
    assert(comms.size() == weights.size());
    
    VectorCommitment result;
    result.value = ZZ(1);
    result.randomness = ZZ(0);
    
    for (size_t i = 0; i < comms.size(); i++) {
        // Scale commitment by weight
        VectorCommitment scaled;
        scaled.value = PowerMod(comms[i].value, weights[i], pp.N * pp.N);
        scaled.randomness = comms[i].randomness * weights[i];
        
        // Add to result
        result.value = MulMod(result.value, scaled.value, pp.N * pp.N);
        result.randomness = result.randomness + scaled.randomness;
    }
    
    return result;
}

} // namespace CS
