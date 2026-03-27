/*
 * Simple Example: Multi-Key Camenisch-Shoup Encryption
 */

#include <iostream>
#include "../include/cs_context.hpp"

using namespace PIS_CA;
using namespace std;

int main() {
    cout << "=== PIS-CA Refactored: Simple Multi-Key Example ===" << endl;
    
    // -------------------------------------------------------------
    // 1. 初始化系统：3个密钥对，4维承诺系统
    // --------------------------------------------------------------
    cout << "\n[1] Initializing system with 3 key pairs..." << endl;
    SystemParams params(3, 4);  // keyCount=3, commitDimension=4
    CSContext ctx(params);
    
    cout << "    Generated " << ctx.getKeyCount() << " key pairs with unified generator g" << endl;
    cout << "    Commitment key dimension: " << ctx.getCommitKey().getDimension() << endl;
    
    // -------------------------------------------------------------
    // 2. 展示统一生成元g的使用
    // --------------------------------------------------------------
    cout << "\n[2] All keys share the same generator g:" << endl;
    for (size_t i = 0; i < ctx.getKeyCount(); ++i) {
        const CSKeyPair& kp = ctx.getKeyPair(i);
        cout << "    Key " << i << ": x_" << i << " = [secret], pk_" << i << " = g^x_" << i << endl;
    }
    
    // -------------------------------------------------------------
    // 3. 用不同密钥加密相同消息
    // --------------------------------------------------------------
    cout << "\n[3] Encrypting same message with different keys:" << endl;
    MessageVector msg = {ZZ(100), ZZ(200), ZZ(300), ZZ(400)};
    cout << "    Message: [100, 200, 300, 400]" << endl;
    
    vector<CSCiphertext> ciphertexts;
    for (size_t i = 0; i < ctx.getKeyCount(); ++i) {
        ciphertexts.push_back(ctx.encrypt(i, msg));
        cout << "    Ciphertext " << i << " created with key " << i << endl;
    }
    
    // -------------------------------------------------------------
    // 4. 只能用对应密钥解密
    // --------------------------------------------------------------
    cout << "\n[4] Decryption verification:" << endl;
    for (size_t i = 0; i < ctx.getKeyCount(); ++i) {
        MessageVector decrypted = ctx.decrypt(i, ciphertexts[i]);
        bool correct = (decrypted == msg);
        cout << "    Key " << i << " decrypts ciphertext " << i << ": " 
             << (correct ? "✓ CORRECT" : "✗ FAILED") << endl;
    }
    
    // -------------------------------------------------------------
    // 5. 承诺操作示例
    // --------------------------------------------------------------
    cout << "\n[5] Commitment operations:" << endl;
    MessageVector commitMsg = {ZZ(10), ZZ(20), ZZ(30), ZZ(40)};
    cout << "    Committing to [10, 20, 30, 40]..." << endl;
    
    ZZ r;
    RandomBits(r, 128);
    CSCommitment com = ctx.commit(commitMsg, &r);
    
    bool verified = ctx.verifyCommitment(com, commitMsg, r);
    cout << "    Verification: " << (verified ? "✓ PASSED" : "✗ FAILED") << endl;
    
    // -------------------------------------------------------------
    // 6. 动态扩展演示
    // --------------------------------------------------------------
    cout << "\n[6] Dynamic extension demonstration:" << endl;
    cout << "    Current key count: " << ctx.getKeyCount() << endl;
    cout << "    Adding new key pair..." << endl;
    ctx.addKeyPair();
    cout << "    New key count: " << ctx.getKeyCount() << endl;
    
    cout << "\n    Current commit dimension: " << ctx.getCommitKey().getDimension() << endl;
    cout << "    Extending to 8 dimensions..." << endl;
    ctx.extendCommitDimension(8);
    cout << "    New commit dimension: " << ctx.getCommitKey().getDimension() << endl;
    
    // 使用扩展后的维度
    MessageVector extendedMsg;
    for (int i = 0; i < 8; ++i) {
        extendedMsg.push_back(ZZ((i + 1) * 10));
    }
    CSCommitment extendedCom = ctx.commit(extendedMsg);
    cout << "    Successfully committed to 8-dimensional vector" << endl;
    
    // -------------------------------------------------------------
    // 7. 同态运算演示
    // --------------------------------------------------------------
    cout << "\n[7] Homomorphic addition demo:" << endl;
    MessageVector m1 = {ZZ(50), ZZ(100), ZZ(150), ZZ(200)};
    MessageVector m2 = {ZZ(25), ZZ(50), ZZ(75), ZZ(100)};
    
    CSCiphertext ct1 = ctx.encrypt(0, m1);
    CSCiphertext ct2 = ctx.encrypt(0, m2);
    CSCiphertext ctSum = ctx.homoAdd(ct1, ct2);
    
    MessageVector decryptedSum = ctx.decrypt(0, ctSum);
    cout << "    m1 = [50, 100, 150, 200]" << endl;
    cout << "    m2 = [25, 50, 75, 100]" << endl;
    cout << "    m1 + m2 = [";
    for (size_t i = 0; i < decryptedSum.size(); ++i) {
        cout << decryptedSum[i] << (i < decryptedSum.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;
    
    cout << "\n=== Example Complete ===" << endl;
    return 0;
}
