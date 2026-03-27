/*
 * CS Encryption Implementation
 */

#include "../include/cs_encryption.hpp"

namespace PIS_CA {

CSPublicParams CSEncryption::setup(const SystemParams& params) {
    CSPublicParams publicParams;
    
    // Generate safe primes
    ZZ primeP, primeQ;
    GenGermainPrime(primeP, params.primeBits);
    GenGermainPrime(primeQ, params.primeBits);
    
    // RSA modulus
    publicParams.rsaModulus = primeP * primeQ;
    publicParams.rsaSubgroupOrder = ((primeP - 1) / 2) * ((primeQ - 1) / 2);
    
    // Compute N^zeta and N^(zeta+1)
    publicParams.nToZeta = ZZ(1);
    publicParams.nToZetaPlus1 = publicParams.rsaModulus;
    for (uint32_t i = 1; i <= params.zeta; ++i) {
        publicParams.nToZeta *= publicParams.rsaModulus;
        publicParams.nToZetaPlus1 *= publicParams.rsaModulus;
    }
    
    // Store runtime parameters
    publicParams.messageVectorDimension = params.defaultS;
    publicParams.messageBitLength = params.bBits;
    
    // Default generator T = (1 + N) mod N^(zeta+1)
    publicParams.T = AddMod(ZZ(1), publicParams.rsaModulus, publicParams.nToZetaPlus1);
    
    // Compute 2^B for message encoding
    publicParams.messageRangeBase = PowerMod(ZZ(2), params.bBits - 5, publicParams.nToZetaPlus1);
    
    // Precompute powers of 2^B
    precomputePowerTwoB(publicParams, params.defaultS);
    
    // Generate unified generator g
    ZZ generatorCandidate;
    while (true) {
        RandomLen(generatorCandidate, 2 * params.primeBits - 2);
        ZZ gcdValue = GCD(generatorCandidate, publicParams.nToZetaPlus1);
        if (gcdValue == 1) {
            break;
        }
    }
    publicParams.sharedGenerator = PowerMod(generatorCandidate, 2 * publicParams.nToZeta, publicParams.nToZetaPlus1);
    
    return publicParams;
}

std::vector<CSKeyPair> CSEncryption::generateKeyPairs(
    const CSPublicParams& publicParams,
    const SystemParams& params
) {
    std::vector<CSKeyPair> keyPairs;
    keyPairs.reserve(params.keyCount);
    
    for (uint32_t i = 0; i < params.keyCount; ++i) {
        CSKeyPair keyPair(i);
        
        // Generate secret key x_i
        RandomBits(keyPair.secretKey, 2 * params.primeBits - 2);
        
        // Compute public key pk_i = g^x_i mod N^(zeta+1)
        // All keys share the same generator g
        keyPair.publicKey = PowerMod(publicParams.sharedGenerator, keyPair.secretKey, publicParams.nToZetaPlus1);
        
        keyPairs.push_back(std::move(keyPair));
    }
    
    return keyPairs;
}

CSCommitKey CSEncryption::generateCommitKey(
    const CSPublicParams& publicParams,
    const SystemParams& params
) {
    CSCommitKey commitKey(params.commitDimension);
    
    // Generate g[0], g[1], ..., g[commitDimension-1]
    // Each gi is in the subgroup of order N' (RSA modulus subgroup)
    for (uint32_t i = 0; i < params.commitDimension; ++i) {
        ZZ generatorCandidate;
        while (true) {
            RandomBits(generatorCandidate, 2 * params.primeBits - 2);
            // Verify generatorCandidate is in the correct subgroup
            ZZ subgroupCheck = PowerMod(generatorCandidate, publicParams.rsaSubgroupOrder, publicParams.rsaModulus);
            if (subgroupCheck == 1) {
                break;
            }
        }
        commitKey.generators.push_back(generatorCandidate);
    }
    
    // Generate h for randomness
    while (true) {
        RandomBits(commitKey.randomnessGenerator, 2 * params.primeBits - 2);
        ZZ subgroupCheck = PowerMod(commitKey.randomnessGenerator, publicParams.rsaSubgroupOrder, publicParams.rsaModulus);
        if (subgroupCheck == 1) {
            break;
        }
    }
    
    return commitKey;
}

CSCiphertext CSEncryption::encrypt(
    const CSPublicParams& publicParams,
    const CSKeyPair& keyPair,
    const Plaintext& message,
    const ZZ* randomness
) {
    ZZ r_used;
    if (randomness == nullptr) {
        // Generate randomness
        RandomBits(r_used, 2 * params.primeBits - 2);
    } else {
        r_used = *randomness;
    }
    
    return encryptWithRandom(publicParams, keyPair, message, r_used);
}

CSCiphertext CSEncryption::encryptWithRandom(
    const CSPublicParams& publicParams,
    const CSKeyPair& keyPair,
    const Plaintext& message,
    const ZZ& randomness
) {
    // Encode message vector into single integer
    ZZ encodedMessage = encodeMessageVector(publicParams, message);
    
    CSCiphertext ct;
    
    // u = g^r mod N^(zeta+1)
    ct.randomnessComponent = PowerMod(publicParams.sharedGenerator, randomness, publicParams.nToZetaPlus1);
    
    // e = pk^r * (1+N)^m mod N^(zeta+1)
    ZZ pk_r = PowerMod(keyPair.publicKey, randomness, publicParams.nToZetaPlus1);
    ZZ T_m = PowerMod(publicParams.T, encodedMessage, publicParams.nToZetaPlus1);
    ct.encryptedMessage = MulMod(pk_r, T_m, publicParams.nToZetaPlus1);
    
    return ct;
}

Plaintext CSEncryption::decrypt(
    const CSPublicParams& publicParams,
    const ZZ& secretKey,
    const CSCiphertext& ciphertext
) {
    // Recover (1+N)^m = e / (u^x)
    ZZ u_x_inv = InvMod(ciphertext.randomnessComponent, publicParams.nToZetaPlus1);
    u_x_inv = PowerMod(u_x_inv, secretKey, publicParams.nToZetaPlus1);
    ZZ T_m = MulMod(ciphertext.encryptedMessage, u_x_inv, publicParams.nToZetaPlus1);
    
    // Decode m from (1+N)^m using discrete log
    ZZ encodedMessage = decodeDLog(publicParams, T_m, params.zeta);
    
    // Decode message vector
    return decodeMessage(publicParams, encodedMessage, publicParams.powersOfRangeBase.size());
}

CSCiphertext CSEncryption::homomorphicAdd(
    const CSPublicParams& publicParams,
    const CSCiphertext& c1,
    const CSCiphertext& c2
) {
    CSCiphertext result;
    result.randomnessComponent = MulMod(c1.randomnessComponent, c2.randomnessComponent, publicParams.nToZetaPlus1);
    result.encryptedMessage = MulMod(c1.encryptedMessage, c2.encryptedMessage, publicParams.nToZetaPlus1);
    return result;
}

CSCiphertext CSEncryption::homomorphicSub(
    const CSPublicParams& publicParams,
    const CSCiphertext& c1,
    const CSCiphertext& c2
) {
    CSCiphertext neg_c2;
    neg_c2.randomnessComponent = PowerMod(c2.randomnessComponent, -1, publicParams.nToZetaPlus1);
    neg_c2.encryptedMessage = PowerMod(c2.encryptedMessage, -1, publicParams.nToZetaPlus1);
    return homomorphicAdd(publicParams, c1, neg_c2);
}

CSCiphertext CSEncryption::scalarMultiply(
    const CSPublicParams& publicParams,
    const CSCiphertext& c,
    const ZZ& scalar
) {
    CSCiphertext result;
    result.randomnessComponent = PowerMod(c.randomnessComponent, scalar, publicParams.nToZetaPlus1);
    result.encryptedMessage = PowerMod(c.encryptedMessage, scalar, publicParams.nToZetaPlus1);
    return result;
}

// Private helper implementations

ZZ CSEncryption::computeL(const CSPublicParams& publicParams, const ZZ& m) {
    ZZ f = m - 1;
    return f / publicParams.rsaModulus;
}

ZZ CSEncryption::decodeDLog(const CSPublicParams& publicParams, const ZZ& value, uint32_t zeta) {
    ZZ i = ZZ(0);
    
    for (uint32_t j = 1; j <= zeta; ++j) {
        ZZ nj = power(publicParams.rsaModulus, j);
        
        // Compute L(value) mod nj
        ZZ t1 = computeL(publicParams, value);
        ZZ t2 = i;
        
        for (uint32_t k = 2; k <= j; ++k) {
            ZZ nk1 = power(publicParams.rsaModulus, k - 1);
            ZZ k1 = ZZ(1);
            for (uint32_t a = 1; a < k; ++a) {
                nk1 *= publicParams.rsaModulus;
                k1 *= a;
            }
            k1 *= k;
            
            // Update with binomial correction terms
            i = i - 1;
            t2 = MulMod(t2, i, nj);
            ZZ t3 = MulMod(t2, nk1, nj);
            ZZ t4 = InvMod(k1, nj);
            t3 = MulMod(t3, t4, nj);
            t1 = SubMod(t1, t3, nj);
        }
        i = t1;
    }
    
    return i;
}

ZZ CSEncryption::encodeMessageVector(
    const CSPublicParams& publicParams,
    const Plaintext& message
) {
    ZZ encoded = ZZ(0);
    
    for (size_t i = 0; i < message.size(); ++i) {
        ZZ weighted;
        if (i < publicParams.powersOfRangeBase.size()) {
            mul(weighted, message[i], publicParams.powersOfRangeBase[i]);
        } else {
            mul(weighted, message[i], power(publicParams.messageRangeBase, i));
        }
        add(encoded, encoded, weighted);
    }
    
    return encoded;
}

Plaintext CSEncryption::decodeMessage(
    const CSPublicParams& publicParams,
    const ZZ& encoded,
    uint32_t dimension
) {
    Plaintext message;
    message.reserve(dimension);
    
    ZZ remaining = encoded;
    
    // Decode from most significant to least
    for (int32_t i = static_cast<int32_t>(dimension) - 1; i >= 0; --i) {
        ZZ two_B_i = (i < static_cast<int32_t>(publicParams.powersOfRangeBase.size())) 
                       ? publicParams.powersOfRangeBase[i] 
                       : power(publicParams.messageRangeBase, i);
        
        ZZ mi = remaining / two_B_i;
        message.push_back(mi);
        
        ZZ subtracted;
        mul(subtracted, mi, two_B_i);
        sub(remaining, remaining, subtracted);
    }
    
    std::reverse(message.begin(), message.end());
    return message;
}

ZZ CSEncryption::generateRandom(const ZZ& modulus) {
    ZZ r;
    RandomBits(r, NumBits(modulus) - 10);
    return r;
}

void CSEncryption::precomputePowerTwoB(CSPublicParams& publicParams, uint32_t maxDimension) {
    publicParams.powersOfRangeBase.reserve(maxDimension);
    for (uint32_t i = 0; i < maxDimension; ++i) {
        publicParams.powersOfRangeBase.push_back(power(publicParams.messageRangeBase, i));
    }
}

} // namespace PIS_CA
