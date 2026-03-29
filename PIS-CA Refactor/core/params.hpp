#pragma once

#include <NTL/ZZ.h>
#include <vector>

using namespace NTL;

namespace CS {

// System parameters
struct SystemParams {
    uint32_t primeLengths;        // Prime length (default 768)
    uint32_t zeta;                // Power exponent (default 2)
    uint32_t subPlaintextLengths; // Subplaintext length (default 768)
    uint32_t batchEncSize;        // Number of messages per ciphertext (default 4)
    uint32_t batchShareSize;      // Batch sharing size
    
    SystemParams(uint32_t pLen = 768, uint32_t z = 2, uint32_t sLen = 768, 
                 uint32_t batchEnc = 4, uint32_t batchShare = 4)
        : primeLengths(pLen), zeta(z), subPlaintextLengths(sLen), 
          batchEncSize(batchEnc), batchShareSize(batchShare) {}
};

// Public parameters (generated during setup)
struct PublicParams {
    ZZ N;              // RSA modulus
    ZZ N_prime;        // N' = ((p-1)/2) * ((q-1)/2)
    ZZ N_zeta;         // N^zeta
    ZZ N_zeta_1;       // N^(zeta+1)
    ZZ T;              // (1+N) mod N^(zeta+1)
    ZZ g;              // Generator
    
    // Batch encryption specific
    ZZ two_B;          // 2^B
    std::vector<ZZ> powTwoB;  // Precomputed powers of 2^B
    
    void precomputePowTwoB(uint32_t maxDim, uint32_t bBits);
};

// Key pair
struct KeyPair {
    ZZ x;              // Secret key
    ZZ y;              // Public key y = g^x mod N_zeta
};

// Ciphertext structures
struct SingleCiphertext {
    ZZ u;              // g^r
    ZZ e;              // y^r * (1+N)^m
};

struct BatchCiphertext {
    ZZ u;                          // Common g^r
    std::vector<ZZ> e;             // Multiple e_i for each batch element
    uint32_t batchSize;
};

// Commitment structures
struct CommitKey {
    std::vector<ZZ> g;   // Generators for message components
    ZZ h;                // Generator for randomness
};

struct VectorCommitment {
    ZZ value;            // Commitment value
    ZZ randomness;       // Opening value
};

// Type aliases
using Plaintext = std::vector<ZZ>;

} // namespace CS
