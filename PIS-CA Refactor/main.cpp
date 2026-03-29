#include <iostream>
#include <vector>
#include <chrono>
#include "core/params.hpp"
#include "core/encryption.hpp"
#include "commitment/vector_commitment.hpp"

using namespace std;
using namespace CS;

void testSingleEncryption() {
    cout << "\n=== Single Encryption Test ===" << endl;
    
    SystemParams sp(512, 2, 768, 4);  // Smaller primes for testing
    PublicParams pp;
    Encryption::setup(pp, sp);
    
    KeyPair kp = Encryption::generateKeyPair(pp, sp);
    
    ZZ message = ZZ(12345);
    SingleCiphertext ct;
    ZZ r;
    
    Encryption::encrypt(pp, kp, message, ct, r);
    ZZ decrypted = Encryption::decrypt(pp, kp, ct);
    
    cout << "Original: " << message << endl;
    cout << "Decrypted: " << decrypted << endl;
    cout << "Test: " << (message == decrypted ? "PASSED" : "FAILED") << endl;
}

void testBatchEncryptionSameRandom() {
    cout << "\n=== Batch Encryption (Same Random) Test ===" << endl;
    
    SystemParams sp(512, 2, 768, 4);
    PublicParams pp;
    Encryption::setup(pp, sp);
    
    KeyPair kp = Encryption::generateKeyPair(pp, sp);
    
    Plaintext messages = {ZZ(100), ZZ(200), ZZ(300), ZZ(400)};
    BatchCiphertext ct;
    ZZ r;
    
    Encryption::encryptBatchSameRandom(pp, kp, messages, ct, r);
    Plaintext decrypted = Encryption::decryptBatchSameRandom(pp, kp, ct);
    
    cout << "Original: ";
    for (auto& m : messages) cout << m << " ";
    cout << endl;
    
    cout << "Decrypted: ";
    for (auto& m : decrypted) cout << m << " ";
    cout << endl;
    
    bool pass = (messages.size() == decrypted.size());
    for (size_t i = 0; i < messages.size() && i < decrypted.size(); i++) {
        if (messages[i] != decrypted[i]) pass = false;
    }
    cout << "Test: " << (pass ? "PASSED" : "FAILED") << endl;
}

void testBatchEncryptionDifferentRandom() {
    cout << "\n=== Batch Encryption (Different Random) Test ===" << endl;
    
    SystemParams sp(512, 2, 768, 4);
    PublicParams pp;
    Encryption::setup(pp, sp);
    
    KeyPair kp = Encryption::generateKeyPair(pp, sp);
    
    Plaintext messages = {ZZ(111), ZZ(222), ZZ(333), ZZ(444)};
    BatchCiphertext ct;
    vector<ZZ> randomness;
    
    Encryption::encryptBatchDifferentRandom(pp, kp, messages, ct, randomness);
    Plaintext decrypted = Encryption::decryptBatchDifferentRandom(pp, kp, ct, randomness);
    
    cout << "Original: ";
    for (auto& m : messages) cout << m << " ";
    cout << endl;
    
    cout << "Decrypted: ";
    for (auto& m : decrypted) cout << m << " ";
    cout << endl;
    
    bool pass = (messages.size() == decrypted.size());
    for (size_t i = 0; i < messages.size() && i < decrypted.size(); i++) {
        if (messages[i] != decrypted[i]) pass = false;
    }
    cout << "Test: " << (pass ? "PASSED" : "FAILED") << endl;
}

void testVectorCommitment() {
    cout << "\n=== Vector Commitment Test ===" << endl;
    
    SystemParams sp(512, 2, 768, 4);
    PublicParams pp;
    Encryption::setup(pp, sp);
    
    // Setup commitment key
    CommitKey ck = VectorCommitmentScheme::setup(pp, 4);
    
    // Commit to vector
    Plaintext vector = {ZZ(10), ZZ(20), ZZ(30), ZZ(40)};
    ZZ randomness = ZZ(42);
    VectorCommitment comm = VectorCommitmentScheme::commit(pp, ck, vector, randomness);
    
    cout << "Commitment value: " << comm.value << endl;
    
    // Verify
    bool verified = VectorCommitmentScheme::verify(pp, ck, comm, vector, randomness);
    cout << "Verification: " << (verified ? "PASSED" : "FAILED") << endl;
    
    // Test homomorphic addition
    Plaintext vector2 = {ZZ(5), ZZ(15), ZZ(25), ZZ(35)};
    ZZ randomness2 = ZZ(24);
    VectorCommitment comm2 = VectorCommitmentScheme::commit(pp, ck, vector2, randomness2);
    
    VectorCommitment commSum = VectorCommitmentScheme::add(pp, ck, comm, comm2);
    
    // Verify sum commitment
    Plaintext vectorSum = {ZZ(15), ZZ(35), ZZ(55), ZZ(75)};
    ZZ randomnessSum = randomness + randomness2;
    bool sumVerified = VectorCommitmentScheme::verify(pp, ck, commSum, vectorSum, randomnessSum);
    cout << "Homomorphic addition: " << (sumVerified ? "PASSED" : "FAILED") << endl;
    
    // Test scalar multiplication
    ZZ scalar = ZZ(3);
    VectorCommitment commScaled = VectorCommitmentScheme::scalarMul(pp, ck, comm, scalar);
    
    Plaintext vectorScaled = {ZZ(30), ZZ(60), ZZ(90), ZZ(120)};
    ZZ randomnessScaled = randomness * scalar;
    bool scaledVerified = VectorCommitmentScheme::verify(pp, ck, commScaled, vectorScaled, randomnessScaled);
    cout << "Scalar multiplication: " << (scaledVerified ? "PASSED" : "FAILED") << endl;
}

void testHomomorphicOperations() {
    cout << "\n=== Homomorphic Operations Test ===" << endl;
    
    SystemParams sp(512, 2, 768, 4);
    PublicParams pp;
    Encryption::setup(pp, sp);
    
    KeyPair kp = Encryption::generateKeyPair(pp, sp);
    
    // Encrypt two messages
    ZZ m1 = ZZ(100);
    ZZ m2 = ZZ(50);
    
    SingleCiphertext ct1, ct2;
    ZZ r1, r2;
    Encryption::encrypt(pp, kp, m1, ct1, r1);
    Encryption::encrypt(pp, kp, m2, ct2, r2);
    
    // Homomorphic addition (m1 + m2)
    SingleCiphertext ctSum = Encryption::homomorphicAdd(pp, ct1, ct2);
    ZZ decryptedSum = Encryption::decrypt(pp, kp, ctSum);
    
    cout << m1 << " + " << m2 << " = " << decryptedSum << endl;
    cout << "Addition: " << (decryptedSum == m1 + m2 ? "PASSED" : "FAILED") << endl;
    
    // Homomorphic subtraction (m1 - m2)
    SingleCiphertext ctSub = Encryption::homomorphicSub(pp, ct1, ct2);
    ZZ decryptedSub = Encryption::decrypt(pp, kp, ctSub);
    
    cout << m1 << " - " << m2 << " = " << decryptedSub << endl;
    cout << "Subtraction: " << (decryptedSub == m1 - m2 ? "PASSED" : "FAILED") << endl;
    
    // Scalar multiplication (m1 * 3)
    ZZ scalar = ZZ(3);
    SingleCiphertext ctScaled = Encryption::scalarMultiply(pp, ct1, scalar);
    ZZ decryptedScaled = Encryption::decrypt(pp, kp, ctScaled);
    
    cout << m1 << " * " << scalar << " = " << decryptedScaled << endl;
    cout << "Scalar multiply: " << (decryptedScaled == m1 * scalar ? "PASSED" : "FAILED") << endl;
}

int main() {
    cout << "========================================" << endl;
    cout << "  Camenisch-Shoup Encryption Tests" << endl;
    cout << "========================================" << endl;
    
    auto start = chrono::high_resolution_clock::now();
    
    testSingleEncryption();
    testBatchEncryptionSameRandom();
    testBatchEncryptionDifferentRandom();
    testVectorCommitment();
    testHomomorphicOperations();
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    cout << "\n========================================" << endl;
    cout << "  All tests completed in " << duration.count() << " ms" << endl;
    cout << "========================================" << endl;
    
    return 0;
}
