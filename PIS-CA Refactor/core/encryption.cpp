#include "encryption.hpp"
#include <NTL/ZZ.h>

using namespace NTL;

namespace CS {

void PublicParams::precomputePowTwoB(uint32_t maxDim, uint32_t bBits) {
    powTwoB.resize(maxDim);
    ZZ base = power(ZZ(2), bBits);
    powTwoB[0] = ZZ(1);
    for (uint32_t i = 1; i < maxDim; i++) {
        powTwoB[i] = powTwoB[i-1] * base;
    }
}

void Encryption::setup(PublicParams& pp, const SystemParams& sp) {
    // Generate RSA modulus
    ZZ p, q;
    GenPrime(p, sp.primeLengths);
    GenPrime(q, sp.primeLengths);
    
    pp.N = p * q;
    pp.N_prime = ((p - 1) / 2) * ((q - 1) / 2);
    pp.N_zeta = power(pp.N, sp.zeta);
    pp.N_zeta_1 = pp.N_zeta * pp.N;
    
    // T = (1 + N) mod N^(zeta+1)
    pp.T = (ZZ(1) + pp.N) % pp.N_zeta_1;
    
    // Find generator in QR_N
    pp.g = ZZ(1);
    while (pp.g == 1 || Jacobi(pp.g, pp.N) != 1) {
        pp.g = RandomBnd(pp.N);
    }
    
    // Precompute powers
    pp.two_B = power(ZZ(2), sp.subPlaintextLengths);
    pp.precomputePowTwoB(sp.batchEncSize * 2, sp.subPlaintextLengths);
}

KeyPair Encryption::generateKeyPair(const PublicParams& pp, const SystemParams& sp) {
    KeyPair kp;
    // x in [0, N/4]
    kp.x = RandomBnd(pp.N / 4);
    // y = g^x mod N_zeta
    kp.y = PowerMod(pp.g, kp.x, pp.N_zeta);
    return kp;
}

ZZ Encryption::computeL(const PublicParams& pp, const ZZ& value) {
    return (value - 1) / pp.N;
}

ZZ Encryption::encodeBatch(const PublicParams& pp, const Plaintext& messages) {
    ZZ encoded = ZZ(0);
    for (size_t i = 0; i < messages.size() && i < pp.powTwoB.size(); i++) {
        encoded += messages[i] * pp.powTwoB[i];
    }
    return encoded;
}

Plaintext Encryption::decodeBatch(const PublicParams& pp, const ZZ& encoded, uint32_t count) {
    Plaintext messages(count);
    ZZ temp = encoded;
    for (uint32_t i = 0; i < count; i++) {
        messages[i] = temp % pp.two_B;
        temp = temp / pp.two_B;
    }
    return messages;
}

void Encryption::encrypt(
    const PublicParams& pp,
    const KeyPair& kp,
    const ZZ& message,
    SingleCiphertext& ct,
    ZZ& randomness
) {
    randomness = RandomBnd(pp.N / 4);
    
    // u = g^r mod N_zeta
    ct.u = PowerMod(pp.g, randomness, pp.N_zeta);
    
    // e = y^r * T^m mod N_zeta_1
    ZZ y_r = PowerMod(kp.y, randomness, pp.N_zeta_1);
    ZZ T_m = PowerMod(pp.T, message, pp.N_zeta_1);
    ct.e = MulMod(y_r, T_m, pp.N_zeta_1);
}

ZZ Encryption::decrypt(
    const PublicParams& pp,
    const KeyPair& kp,
    const SingleCiphertext& ct
) {
    // Compute u^x mod N_zeta_1
    ZZ u_x = PowerMod(ct.u, kp.x, pp.N_zeta_1);
    
    // T^m = e / u^x mod N_zeta_1
    ZZ T_m = MulMod(ct.e, InvMod(u_x, pp.N_zeta_1), pp.N_zeta_1);
    
    // m = L(T^m)
    return computeL(pp, T_m);
}

// Batch Type 1: Same randomness for all messages
void Encryption::encryptBatchSameRandom(
    const PublicParams& pp,
    const KeyPair& kp,
    const Plaintext& messages,
    BatchCiphertext& ct,
    ZZ& randomness
) {
    randomness = RandomBnd(pp.N / 4);
    ct.batchSize = messages.size();
    ct.e.resize(ct.batchSize);
    
    // Common u = g^r
    ct.u = PowerMod(pp.g, randomness, pp.N_zeta);
    
    // Each e_i = y^r * T^(encode(m_i))
    ZZ y_r = PowerMod(kp.y, randomness, pp.N_zeta_1);
    
    for (size_t i = 0; i < messages.size(); i++) {
        ZZ T_m = PowerMod(pp.T, messages[i], pp.N_zeta_1);
        ct.e[i] = MulMod(y_r, T_m, pp.N_zeta_1);
    }
}

Plaintext Encryption::decryptBatchSameRandom(
    const PublicParams& pp,
    const KeyPair& kp,
    const BatchCiphertext& ct
) {
    Plaintext messages(ct.batchSize);
    
    // Compute u^x once
    ZZ u_x = PowerMod(ct.u, kp.x, pp.N_zeta_1);
    ZZ u_x_inv = InvMod(u_x, pp.N_zeta_1);
    
    for (size_t i = 0; i < ct.batchSize; i++) {
        // T^m_i = e_i / u^x
        ZZ T_m = MulMod(ct.e[i], u_x_inv, pp.N_zeta_1);
        messages[i] = computeL(pp, T_m);
    }
    
    return messages;
}

// Batch Type 2: Different randomness per message
void Encryption::encryptBatchDifferentRandom(
    const PublicParams& pp,
    const KeyPair& kp,
    const Plaintext& messages,
    BatchCiphertext& ct,
    std::vector<ZZ>& randomness
) {
    ct.batchSize = messages.size();
    ct.e.resize(ct.batchSize);
    randomness.resize(ct.batchSize);
    
    // Common u = product of all g^{r_i}
    ct.u = ZZ(1);
    
    for (size_t i = 0; i < messages.size(); i++) {
        randomness[i] = RandomBnd(pp.N / 4);
        ZZ g_ri = PowerMod(pp.g, randomness[i], pp.N_zeta);
        ct.u = MulMod(ct.u, g_ri, pp.N_zeta);
    }
    
    // Each e_i = y^{r_i} * T^{m_i}
    for (size_t i = 0; i < messages.size(); i++) {
        ZZ y_ri = PowerMod(kp.y, randomness[i], pp.N_zeta_1);
        ZZ T_m = PowerMod(pp.T, messages[i], pp.N_zeta_1);
        ct.e[i] = MulMod(y_ri, T_m, pp.N_zeta_1);
    }
}

Plaintext Encryption::decryptBatchDifferentRandom(
    const PublicParams& pp,
    const KeyPair& kp,
    const BatchCiphertext& ct,
    const std::vector<ZZ>& randomness
) {
    Plaintext messages(ct.batchSize);
    
    for (size_t i = 0; i < ct.batchSize; i++) {
        // Compute u_i = g^{r_i}
        ZZ u_i = PowerMod(pp.g, randomness[i], pp.N_zeta);
        
        // u^x = u_i^x
        ZZ u_i_x = PowerMod(u_i, kp.x, pp.N_zeta_1);
        
        // T^m_i = e_i / u_i^x
        ZZ T_m = MulMod(ct.e[i], InvMod(u_i_x, pp.N_zeta_1), pp.N_zeta_1);
        messages[i] = computeL(pp, T_m);
    }
    
    return messages;
}

// Homomorphic operations
SingleCiphertext Encryption::homomorphicAdd(
    const PublicParams& pp,
    const SingleCiphertext& c1,
    const SingleCiphertext& c2
) {
    SingleCiphertext result;
    result.u = MulMod(c1.u, c2.u, pp.N_zeta);
    result.e = MulMod(c1.e, c2.e, pp.N_zeta_1);
    return result;
}

SingleCiphertext Encryption::homomorphicSub(
    const PublicParams& pp,
    const SingleCiphertext& c1,
    const SingleCiphertext& c2
) {
    SingleCiphertext result;
    result.u = MulMod(c1.u, InvMod(c2.u, pp.N_zeta), pp.N_zeta);
    result.e = MulMod(c1.e, InvMod(c2.e, pp.N_zeta_1), pp.N_zeta_1);
    return result;
}

SingleCiphertext Encryption::scalarMultiply(
    const PublicParams& pp,
    const SingleCiphertext& ct,
    const ZZ& scalar
) {
    SingleCiphertext result;
    result.u = PowerMod(ct.u, scalar, pp.N_zeta);
    result.e = PowerMod(ct.e, scalar, pp.N_zeta_1);
    return result;
}

} // namespace CS
