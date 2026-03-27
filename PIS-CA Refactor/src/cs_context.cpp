/*
 * CS Context Implementation
 */

#include "../include/cs_context.hpp"
#include <stdexcept>

namespace PIS_CA {

CSContext::CSContext() : initialized_(false) {}

CSContext::CSContext(const SystemParams& params) : initialized_(false) {
    initialize(params);
}

void CSContext::initialize(const SystemParams& params) {
    systemParams_ = params;
    
    // Generate public parameters (includes unified generator g)
    publicParams_ = CSEncryption::setup(params);
    
    // Generate multiple key pairs with shared g
    keyPairs_ = CSEncryption::generateKeyPairs(publicParams_, params);
    
    // Generate commitment key with specified dimension
    commitKey_ = CSEncryption::generateCommitKey(publicParams_, params);
    
    initialized_ = true;
}

const CSKeyPair& CSContext::getKeyPair(size_t index) const {
    if (index >= keyPairs_.size()) {
        throw std::out_of_range("Key pair index out of range");
    }
    return keyPairs_[index];
}

void CSContext::addKeyPair() {
    // Generate additional key pair with same generator g
    CSKeyPair keyPair(static_cast<uint32_t>(keyPairs_.size()));
    RandomBits(keyPair.secretKey, 2 * systemParams_.primeBits - 2);
    keyPair.publicKey = PowerMod(publicParams_.sharedGenerator, keyPair.secretKey, publicParams_.nToZetaPlus1);
    keyPairs_.push_back(keyPair);
    systemParams_.keyCount++;
}

void CSContext::extendCommitDimension(uint32_t newDimension) {
    CSCommitmentUtils::extendDimension(publicParams_, commitKey_, newDimension, systemParams_.primeBits);
    systemParams_.commitDimension = newDimension;
}

CSCiphertext CSContext::encrypt(
    size_t keyIndex,
    const Plaintext& message,
    const ZZ* randomness
) const {
    const CSKeyPair& keyPair = getKeyPair(keyIndex);
    return CSEncryption::encrypt(publicParams_, keyPair, message, randomness);
}

Plaintext CSContext::decrypt(size_t keyIndex, const CSCiphertext& ciphertext) const {
    const CSKeyPair& keyPair = getKeyPair(keyIndex);
    return CSEncryption::decrypt(publicParams_, keyPair.secretKey, ciphertext);
}

CSCiphertext CSContext::homoAdd(const CSCiphertext& c1, const CSCiphertext& c2) const {
    return CSEncryption::homomorphicAdd(publicParams_, c1, c2);
}

CSCiphertext CSContext::homoSub(const CSCiphertext& c1, const CSCiphertext& c2) const {
    return CSEncryption::homomorphicSub(publicParams_, c1, c2);
}

CSCiphertext CSContext::scalarMul(const CSCiphertext& c, const ZZ& scalar) const {
    return CSEncryption::scalarMultiply(publicParams_, c, scalar);
}

CSCommitment CSContext::commit(const Plaintext& messages, const ZZ* randomness) const {
    return CSCommitmentScheme::commit(publicParams_, commitKey_, messages, randomness);
}

bool CSContext::verifyCommitment(
    const CSCommitment& commitment,
    const Plaintext& messages,
    const ZZ& randomness
) const {
    return CSCommitmentScheme::verify(publicParams_, commitKey_, commitment, messages, randomness);
}

CSCommitment CSContext::commitAdd(const CSCommitment& c1, const CSCommitment& c2) const {
    return CSCommitmentScheme::add(publicParams_, c1, c2);
}

CSCommitment CSContext::commitScalarMul(const CSCommitment& c, const ZZ& scalar) const {
    return CSCommitmentScheme::scalarMul(publicParams_, c, scalar);
}

} // namespace PIS_CA
