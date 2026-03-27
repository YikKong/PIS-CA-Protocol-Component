/*
 * Utility Functions for CS Operations
 */

#pragma once

#include "cs_types.hpp"
#include <string>
#include <vector>

namespace PIS_CA {

/**
 * @brief String <-> ZZ conversion utilities
 * 提供字符串与大整数(ZZ)之间的相互转换，以及字节数组的十六进制编码/解码
 */
class StringUtils {
public:
    /**
     * @brief 将十进制字符串转换为大整数 ZZ
     * @param str 十进制数字字符串 (如 "123456")
     * @return 对应的 ZZ 大整数值
     */
    static ZZ stringToZZ(const std::string& str);
    
    /**
     * @brief 将大整数 ZZ 转换为十进制字符串
     * @param num ZZ 大整数
     * @return 十进制字符串表示
     */
    static std::string ZZToString(const ZZ& num);
    
    /**
     * @brief 将字节数组转换为十六进制字符串
     * @param data 字节数组指针
     * @param len 字节数组长度
     * @return 十六进制字符串 (如 "a1b2c3")
     */
    static std::string bytesToHex(const uint8_t* data, size_t len);
    
    /**
     * @brief 将十六进制字符串转换为字节数组
     * @param hex 十六进制字符串
     * @return 字节数组
     */
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
};

/**
 * @brief Random Oracle / Hash utilities
 * 提供密码学哈希函数(SHA256)和随机预言机功能，用于挑战生成和哈希承诺
 */
class HashUtils {
public:
    static constexpr size_t HASH_BYTES = 32; // SHA256 输出长度
    
    /**
     * @brief 计算字符串的 SHA256 哈希值
     * @param input 输入字符串
     * @param output 32字节哈希输出数组
     */
    static void sha256(const std::string& input, uint8_t output[HASH_BYTES]);
    
    /**
     * @brief 计算字节数组的 SHA256 哈希值
     * @param input 输入字节数组
     * @param len 输入长度
     * @param output 32字节哈希输出数组
     */
    static void sha256(const uint8_t* input, size_t len, uint8_t output[HASH_BYTES]);
    
    /**
     * @brief 将大整数 ZZ 哈希为另一个 ZZ
     * 用于将任意大整数映射到有限域元素
     * @param input 输入大整数
     * @return 哈希后的 ZZ 值
     */
    static ZZ hashToZZ(const ZZ& input);
    
    /**
     * @brief 将字符串哈希为大整数 ZZ
     * @param input 输入字符串
     * @return 哈希后的 ZZ 值
     */
    static ZZ hashToZZ(const std::string& input);
    
    /**
     * @brief 从承诺值生成挑战（Fiat-Shamir 变换）
     * 将交互式证明转换为非交互式，通过哈希承诺生成随机挑战
     * @param commitment 承诺值
     * @return 随机挑战值
     */
    static ZZ generateChallenge(const ZZ& commitment);
    
    /**
     * @brief 从向量值生成挑战
     * 对多个值的承诺生成单一挑战值
     * @param values 大整数向量
     * @return 随机挑战值
     */
    static ZZ generateChallenge(const std::vector<ZZ>& values);
};

/**
 * @brief Mathematical utilities
 * 提供数论运算工具，包括扩展欧几里得算法、模逆元、安全素数生成等密码学常用数学操作
 */
class MathUtils {
public:
    /**
     * @brief Extended Euclidean Algorithm (求解 ax + by = gcd(a,b))
     * 计算两个大整数的最大公约数，同时找到满足贝祖等式的系数 x 和 y
     * @param a 第一个大整数
     * @param b 第二个大整数
     * @param x 输出参数，满足 ax + by = gcd(a,b) 的系数 x
     * @param y 输出参数，满足 ax + by = gcd(a,b) 的系数 y
     * @return a 和 b 的最大公约数 gcd(a,b)
     */
    static ZZ extendedEuclideanGcd(const ZZ& a, const ZZ& b, ZZ& x, ZZ& y);
    
    /**
     * @brief 计算模逆元
     * 求 a 在模 m 下的乘法逆元，即满足 a * x ≡ 1 (mod m) 的 x
     * @param a 待求逆元的整数
     * @param m 模数
     * @return a 的模逆元
     * @note 要求 a 和 m 互质，否则逆元不存在
     */
    static ZZ modInv(const ZZ& a, const ZZ& m);
    
    /**
     * @brief 生成安全素数（Sophie Germain 素数）
     * 生成一个素数 p，使得 2p+1 也是素数，用于 RSA 等密码系统
     * @param p 输出参数，生成的安全素数
     * @param bits 素数的位长度
     */
    static void generateSafePrime(ZZ& p, long bits);
    
    /**
     * @brief 判断是否为模 n 的二次剩余
     * 检查 a 是否是模 n 的二次剩余，即是否存在 x 满足 x² ≡ a (mod n)
     * @param a 待检查的整数
     * @param n 模数
     * @return true 如果 a 是二次剩余，false 否则
     */
    static bool isQuadraticResidue(const ZZ& a, const ZZ& n);
    
    /**
     * @brief 在乘法群 Z_n^* 中生成随机元素
     * 生成一个与 n 互质的随机整数，用于需要可逆元素的密码学操作
     * @param n 模数，定义乘法群的范围
     * @return Z_n^* 中的随机元素
     */
    static ZZ randomInMultGroup(const ZZ& n);
    
    /**
     * @brief 生成指定位长度的随机大整数
     * @param bitLength 随机数的位长度
     * @return 指定长度的随机 ZZ 大整数
     */
    static ZZ randomBits(uint32_t bitLength);
};

/**
 * @brief Serialization utilities
 * 提供 ZZ、密文和承诺的序列化和反序列化工具
 */
class SerializationUtils {
public:
    /**
     * @brief 将大整数 ZZ 序列化为字节数组
     * @param value 待序列化的 ZZ 大整数
     * @return 字节数组表示，可用于网络传输或存储
     */
    static std::vector<uint8_t> serializeZZ(const ZZ& value);
    
    /**
     * @brief 从字节数组反序列化为大整数 ZZ
     * @param data 字节数组指针
     * @param len 字节数组长度
     * @return 反序列化后的 ZZ 大整数
     */
    static ZZ deserializeZZ(const uint8_t* data, size_t len);
    
    /**
     * @brief 将密文结构序列化为字节数组
     * 序列化密文的随机分量 u 和加密分量 e
     * @param ct 待序列化的密文结构
     * @return 包含密文所有信息的字节数组
     */
    static std::vector<uint8_t> serializeCiphertext(const CSCiphertext& ct);
    
    /**
     * @brief 从字节数组反序列化为密文结构
     * @param data 字节数组指针
     * @param len 字节数组长度
     * @return 反序列化后的密文结构
     */
    static CSCiphertext deserializeCiphertext(const uint8_t* data, size_t len);
    
    /**
     * @brief 将承诺结构序列化为字节数组
     * @param com 待序列化的承诺结构
     * @return 字节数组表示
     */
    static std::vector<uint8_t> serializeCommitment(const CSCommitment& com);
    
    /**
     * @brief 从字节数组反序列化为承诺结构
     * @param data 字节数组指针
     * @param len 字节数组长度
     * @return 反序列化后的承诺结构
     */
    static CSCommitment deserializeCommitment(const uint8_t* data, size_t len);
};

} // namespace PIS_CA
