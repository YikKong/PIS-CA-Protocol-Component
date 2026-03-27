/*
 * Example usage and test of CS Refactored Architecture
 */

#include <iostream>
#include <chrono>
#include "../include/cs_context.hpp"
#include "../include/cs_utils.hpp"

using namespace PIS_CA;
using namespace std;

void printBanner(const string& text) {
    cout << "\n" << string(60, '=') << endl;
    cout << "  " << text << endl;
    cout << string(60, '=') << endl;
}

void testBasicEncryption() {
    printBanner("Test 1: Basic Encryption/Decryption");
    
    // Initialize context with 1 key pair, 4-dim commitment
    SystemParams params(1, 4);
    CSContext context(params);
    
    cout << "System initialized with:" << endl;
    cout << "  - Key pairs: " << context.getKeyCount() << endl;
    cout << "  - Commit dimension: 4" << endl;
    
    // Create message vector
    MessageVector messages;
    messages.push_back(ZZ(42));
    messages.push_back(ZZ(100));
    messages.push_back(ZZ(200));
    messages.push_back(ZZ(300));
    
    cout << "\nEncrypting message vector: [";
    for (size_t i = 0; i < messages.size(); ++i) {
        cout << messages[i] << (i < messages.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;
    
    // Encrypt
    auto start = chrono::high_resolution_clock::now();
    CSCiphertext ct = context.encrypt(0, messages);
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Encryption time: " << duration.count() << " ms" << endl;
    
    // Decrypt
    start = chrono::high_resolution_clock::now();
    MessageVector decrypted = context.decrypt(0, ct);
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Decryption time: " << duration.count() << " ms" << endl;
    
    cout << "\nDecrypted message vector: [";
    for (size_t i = 0; i < decrypted.size(); ++i) {
        cout << decrypted[i] << (i < decrypted.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;
    
    // Verify
    bool success = (messages == decrypted);
    cout << "\nVerification: " << (success ? "PASSED" : "FAILED") << endl;
}

void testMultiKeySupport() {
    printBanner("Test 2: Multi-Key Support (Unified Generator g)");
    
    // Initialize with 3 key pairs
    SystemParams params(3, 4);
    CSContext context(params);
    
    cout << "Generated " << context.getKeyCount() << " key pairs with shared generator g" << endl;
    
    MessageVector messages;
    messages.push_back(ZZ(123));
    messages.push_back(ZZ(456));
    messages.push_back(ZZ(789));
    messages.push_back(ZZ(1000));
    
    // Encrypt with each key pair
    for (size_t i = 0; i < context.getKeyCount(); ++i) {
        cout << "\nUsing Key Pair " << i << ":" << endl;
        
        CSCiphertext ct = context.encrypt(i, messages);
        MessageVector decrypted = context.decrypt(i, ct);
        
        bool success = (messages == decrypted);
        cout << "  Encryption/Decryption: " << (success ? "PASSED" : "FAILED") << endl;
        
        const CSKeyPair& kp = context.getKeyPair(i);
        cout << "  pk_" << i << " = g^x_" << i << " mod N^(zeta+1)" << endl;
    }
    
    // Add an extra key dynamically
    cout << "\nAdding new key pair dynamically..." << endl;
    context.addKeyPair();
    cout << "Total key pairs now: " << context.getKeyCount() << endl;
}

void testCommitmentScheme() {
    printBanner("Test 3: Multi-Dimensional Commitment Scheme");
    
    // Initialize with high-dimensional commitment key
    SystemParams params(1, 8);  // 8-dim commitment
    CSContext context(params);
    
    cout << "Commitment key dimension: 8" << endl;
    
    // Commit to message vector
    MessageVector messages;
    for (int i = 0; i < 8; ++i) {
        messages.push_back(ZZ(i * 100 + 50));
    }
    
    cout << "\nCommitting to message vector: [";
    for (size_t i = 0; i < messages.size(); ++i) {
        cout << messages[i] << (i < messages.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;
    
    ZZ r;
    RandomBits(r, 100);
    
    auto start = chrono::high_resolution_clock::now();
    CSCommitment com = context.commit(messages, &r);
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    cout << "Commitment generated in " << duration.count() << " ms" << endl;
    cout << "Commitment value: " << StringUtils::ZZToString(com.com).substr(0, 50) << "..." << endl;
    
    // Verify
    bool verified = context.verifyCommitment(com, messages, r);
    cout << "Verification: " << (verified ? "PASSED" : "FAILED") << endl;
    
    // Extend dimension dynamically
    cout << "\nExtending commitment dimension to 12..." << endl;
    context.extendCommitDimension(12);
    
    // Commit to extended vector
    MessageVector extendedMessages;
    for (int i = 0; i < 12; ++i) {
        extendedMessages.push_back(ZZ(i * 50 + 25));
    }
    
    CSCommitment extendedCom = context.commit(extendedMessages);
    bool extendedVerified = context.verifyCommitment(extendedCom, extendedMessages, extendedCom.r);
    cout << "Extended commitment verification: " << (extendedVerified ? "PASSED" : "FAILED") << endl;
}

void testHomomorphicOperations() {
    printBanner("Test 4: Homomorphic Operations");
    
    SystemParams params(1, 4);
    CSContext context(params);
    
    // Create two message vectors
    MessageVector m1, m2;
    m1.push_back(ZZ(100)); m1.push_back(ZZ(200)); m1.push_back(ZZ(300)); m1.push_back(ZZ(400));
    m2.push_back(ZZ(50));  m2.push_back(ZZ(100)); m2.push_back(ZZ(150)); m2.push_back(ZZ(200));
    
    cout << "m1 = [100, 200, 300, 400]" << endl;
    cout << "m2 = [50, 100, 150, 200]" << endl;
    
    // Encrypt
    CSCiphertext ct1 = context.encrypt(0, m1);
    CSCiphertext ct2 = context.encrypt(0, m2);
    
    // Test homomorphic addition (c1 + c2 should decrypt to m1 + m2)
    cout << "\nHomomorphic Addition: c_add = c1 + c2" << endl;
    CSCiphertext ct_add = context.homoAdd(ct1, ct2);
    MessageVector m_add = context.decrypt(0, ct_add);
    
    cout << "Decrypted: [";
    for (size_t i = 0; i < m_add.size(); ++i) {
        cout << m_add[i] << (i < m_add.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;
    cout << "Expected: [150, 300, 450, 600]" << endl;
    
    // Test homomorphic subtraction
    cout << "\nHomomorphic Subtraction: c_sub = c1 - c2" << endl;
    CSCiphertext ct_sub = context.homoSub(ct1, ct2);
    MessageVector m_sub = context.decrypt(0, ct_sub);
    
    cout << "Decrypted: [";
    for (size_t i = 0; i < m_sub.size(); ++i) {
        cout << m_sub[i] << (i < m_sub.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;
    cout << "Expected: [50, 100, 150, 200]" << endl;
    
    // Test scalar multiplication
    cout << "\nScalar Multiplication: c_scalar = 2 * c1" << endl;
    CSCiphertext ct_scalar = context.scalarMul(ct1, ZZ(2));
    MessageVector m_scalar = context.decrypt(0, ct_scalar);
    
    cout << "Decrypted: [";
    for (size_t i = 0; i < m_scalar.size(); ++i) {
        cout << m_scalar[i] << (i < m_scalar.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;
    cout << "Expected: [200, 400, 600, 800]" << endl;
}

void testCommitmentHomomorphism() {
    printBanner("Test 5: Commitment Homomorphism");
    
    SystemParams params(1, 4);
    CSContext context(params);
    
    MessageVector m1, m2;
    m1.push_back(ZZ(10)); m1.push_back(ZZ(20)); m1.push_back(ZZ(30)); m1.push_back(ZZ(40));
    m2.push_back(ZZ(5));  m2.push_back(ZZ(10)); m2.push_back(ZZ(15)); m2.push_back(ZZ(20));
    
    ZZ r1, r2;
    RandomBits(r1, 100);
    RandomBits(r2, 100);
    
    CSCommitment com1 = context.commit(m1, &r1);
    CSCommitment com2 = context.commit(m2, &r2);
    
    cout << "Com1 commits to [10, 20, 30, 40]" << endl;
    cout << "Com2 commits to [5, 10, 15, 20]" << endl;
    
    // Commitment addition
    cout << "\nCommitment Addition: com_add = com1 + com2" << endl;
    CSCommitment com_add = context.commitAdd(com1, com2);
    
    // Verify com_add commits to (m1 + m2)
    MessageVector m_add;
    for (size_t i = 0; i < m1.size(); ++i) {
        m_add.push_back(m1[i] + m2[i]);
    }
    ZZ r_add = r1 + r2;
    
    bool verified = context.verifyCommitment(com_add, m_add, r_add);
    cout << "Verification (commits to [15, 30, 45, 60]): " << (verified ? "PASSED" : "FAILED") << endl;
    
    // Commitment scalar multiplication
    cout << "\nCommitment Scalar Mul: com_scalar = 3 * com1" << endl;
    CSCommitment com_scalar = context.commitScalarMul(com1, ZZ(3));
    
    MessageVector m_scalar;
    for (const auto& m : m1) {
        m_scalar.push_back(m * 3);
    }
    ZZ r_scalar = r1 * 3;
    
    bool verified2 = context.verifyCommitment(com_scalar, m_scalar, r_scalar);
    cout << "Verification (commits to [30, 60, 90, 120]): " << (verified2 ? "PASSED" : "FAILED") << endl;
}

void testSerialization() {
    printBanner("Test 6: Serialization");
    
    SystemParams params(1, 4);
    CSContext context(params);
    
    MessageVector messages;
    messages.push_back(ZZ(1111));
    messages.push_back(ZZ(2222));
    messages.push_back(ZZ(3333));
    messages.push_back(ZZ(4444));
    
    // Serialize ciphertext
    CSCiphertext ct = context.encrypt(0, messages);
    vector<uint8_t> ctBytes = SerializationUtils::serializeCiphertext(ct);
    cout << "Ciphertext serialized to " << ctBytes.size() << " bytes" << endl;
    
    CSCiphertext ctDeserialized = SerializationUtils::deserializeCiphertext(ctBytes.data(), ctBytes.size());
    MessageVector decrypted = context.decrypt(0, ctDeserialized);
    
    bool success = (messages == decrypted);
    cout << "Serialization round-trip: " << (success ? "PASSED" : "FAILED") << endl;
    
    // Serialize commitment
    CSCommitment com = context.commit(messages);
    vector<uint8_t> comBytes = SerializationUtils::serializeCommitment(com);
    cout << "\nCommitment serialized to " << comBytes.size() << " bytes" << endl;
    
    CSCommitment comDeserialized = SerializationUtils::deserializeCommitment(comBytes.data(), comBytes.size());
    bool comMatch = (com.com == comDeserialized.com);
    cout << "Commitment serialization: " << (comMatch ? "PASSED" : "FAILED") << endl;
}

int main() {
    cout << string(70, '*') << endl;
    cout << "*  PIS-CA Protocol Component - CS Refactored Architecture Test Suite  *" << endl;
    cout << string(70, '*') << endl;
    
    try {
        testBasicEncryption();
        testMultiKeySupport();
        testCommitmentScheme();
        testHomomorphicOperations();
        testCommitmentHomomorphism();
        testSerialization();
        
        cout << "\n" << string(70, '*') << endl;
        cout << "*                     ALL TESTS COMPLETED                              *" << endl;
        cout << string(70, '*') << endl;
        
    } catch (const exception& e) {
        cerr << "\nTest failed with exception: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
