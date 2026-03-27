/*
 * CS Commitment Scheme Implementation
 */

#include "../include/cs_commitment.hpp"

namespace PIS_CA {

CSCommitment CSCommitmentScheme::commit(
    const CSPublicParams& publicParams,
    const CSCommitKey& commitKey,
    const Plaintext& messages,
    const ZZ* randomness
) {
    ZZ randomnessUsed;
    if (randomness == nullptr) {
        RandomBits(randomnessUsed, NumBits(publicParams.rsaModulus) - 10);
    } else {
        randomnessUsed = *randomness;
    }
    
    CSCommitment commitment;
    commitment.commitmentValue = computeCommitment(publicParams, commitKey, messages, randomnessUsed);
    commitment.randomness = randomnessUsed;
    return commitment;
}

CSCommitment CSCommitmentScheme::commitWithRandom(
    const CSPublicParams& publicParams,
    const CSCommitKey& commitKey,
    const Plaintext& messages,
    const ZZ& randomness
) {
    CSCommitment commitment;
    commitment.commitmentValue = computeCommitment(publicParams, commitKey, messages, randomness);
    commitment.randomness = randomness;
    return commitment;
}

bool CSCommitmentScheme::verify(
    const CSPublicParams& publicParams,
    const CSCommitKey& commitKey,
    const CSCommitment& commitment,
    const Plaintext& messages,
    const ZZ& randomness
) {
    ZZ expected = computeCommitment(publicParams, commitKey, messages, randomness);
    return (commitment.commitmentValue == expected);
}

CSCommitment CSCommitmentScheme::add(
    const CSPublicParams& publicParams,
    const CSCommitment& c1,
    const CSCommitment& c2
) {
    CSCommitment result;
    ZZ nSquared = publicParams.rsaModulus * publicParams.rsaModulus;
    result.commitmentValue = MulMod(c1.commitmentValue, c2.commitmentValue, nSquared);
    add(result.randomness, c1.randomness, c2.randomness);
    return result;
}

CSCommitment CSCommitmentScheme::scalarMul(
    const CSPublicParams& publicParams,
    const CSCommitment& commitment,
    const ZZ& scalar
) {
    CSCommitment result;
    ZZ nSquared = publicParams.rsaModulus * publicParams.rsaModulus;
    result.commitmentValue = PowerMod(commitment.commitmentValue, scalar, nSquared);
    mul(result.randomness, commitment.randomness, scalar);
    return result;
}

CSCommitment CSCommitmentScheme::commitSingle(
    const CSPublicParams& publicParams,
    const CSCommitKey& commitKey,
    const ZZ& message,
    const ZZ* randomness
) {
    Plaintext messages;
    messages.push_back(message);
    return commit(publicParams, commitKey, messages, randomness);
}

ZZ CSCommitmentScheme::computeCommitment(
    const CSPublicParams& publicParams,
    const CSCommitKey& commitKey,
    const Plaintext& messages,
    const ZZ& randomness
) {
    ZZ nSquared = publicParams.rsaModulus * publicParams.rsaModulus;
    
    // Start with h^r
    ZZ commitment = PowerMod(commitKey.randomnessGenerator, randomness, nSquared);
    
    // Multiply by each gi^mi
    for (size_t i = 0; i < messages.size() && i < commitKey.generators.size(); ++i) {
        ZZ gi_mi = PowerMod(commitKey.generators[i], messages[i], nSquared);
        commitment = MulMod(commitment, gi_mi, nSquared);
    }
    
    return commitment;
}

// CSCommitmentUtils implementation

CSCommitKey CSCommitmentUtils::createCommitKey(
    const CSPublicParams& publicParams,
    uint32_t dimension
) {
    SystemParams params(1, dimension);
    return CSEncryption::generateCommitKey(publicParams, params);
}

void CSCommitmentUtils::extendDimension(
    CSPublicParams& publicParams,
    CSCommitKey& commitKey,
    uint32_t newDimension,
    uint32_t primeBits
) {
    if (newDimension <= commitKey.getDimension()) {
        return;
    }
    
    // Generate additional generators
    for (uint32_t i = commitKey.getDimension(); i < newDimension; ++i) {
        ZZ generatorCandidate;
        while (true) {
            RandomBits(generatorCandidate, 2 * primeBits - 2);
            ZZ subgroupCheck = PowerMod(generatorCandidate, publicParams.rsaSubgroupOrder, publicParams.rsaModulus);
            if (subgroupCheck == 1) {
                break;
            }
        }
        commitKey.generators.push_back(generatorCandidate);
    }
}

} // namespace PIS_CA
