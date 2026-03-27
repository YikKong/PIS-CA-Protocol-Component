# PIS-CA Protocol Component - Refactored Architecture

基于Camenisch-Shoup加密算法的重构实现，支持多密钥对管理和可扩展承诺系统。

## 架构特点

### 1. 统一生成元 (Unified Generator g)
- 所有密钥对共享同一个生成元 `g`
- `g` 在系统初始化时统一生成，确保一致性
- 公钥计算公式：`pk_i = g^x_i mod N^(zeta+1)`

### 2. 多密钥对支持 (Multi-Key Pairs)
- 通过 `SystemParams::keyCount` 参数指定密钥对数量
- 每个密钥对包含 `(x_i, pk_i)`，其中 `pk_i = g^x_i`
- 支持动态添加新密钥对 (`addKeyPair()`)
- 所有密钥使用相同的系统参数 `(N, N', g, T, ...)`

### 3. 可扩展承诺系统 (Scalable Commitment)
- 承诺维度通过 `SystemParams::commitDimension` 配置
- 承诺密钥结构：`ck = {g[0], g[1], ..., g[d-1], h}`
- 支持动态扩展承诺维度 (`extendCommitDimension()`)
- 承诺公式：`Com = h^r * ∏(g[i]^m[i]) mod N^2`

## 目录结构

```
PIS-CA Refactor/
├── include/                    # 头文件
│   ├── cs_types.hpp           # 核心类型定义
│   ├── cs_encryption.hpp      # 加密算法接口
│   ├── cs_commitment.hpp      # 承诺系统接口
│   ├── cs_context.hpp         # 统一上下文管理
│   └── cs_utils.hpp           # 工具函数
├── src/                       # 实现文件
│   ├── cs_encryption.cpp      # 加密算法实现
│   ├── cs_commitment.cpp    # 承诺系统实现
│   ├── cs_context.cpp       # 上下文管理实现
│   └── cs_utils.cpp         # 工具函数实现
├── tests/                     # 测试文件
│   └── test_cs_system.cpp   # 系统测试套件
└── CMakeLists.txt            # CMake构建配置
```

## 核心组件

### SystemParams - 系统参数
```cpp
struct SystemParams {
    static constexpr uint32_t PRIME_BITS = 768;    // 安全素数位数
    static constexpr uint32_t ZETA = 2;             // n^s 参数
    static constexpr uint32_t DEFAULT_S = 4;        // 默认消息向量维度
    static constexpr uint32_t B_BITS = 768;         // 消息范围参数
    
    uint32_t keyCount;         // 密钥对数量
    uint32_t commitDimension;  // 承诺维度
};
```

### CSPublicParams - 公共参数
```cpp
struct CSPublicParams {
    ZZ N, N_prime;        // RSA模数
    ZZ N_zeta, N_zeta_1;  // N^zeta, N^(zeta+1)
    ZZ g;                  // 统一生成元 (所有密钥对共享)
    ZZ T;                  // (1+N) mod N^(zeta+1)
    ZZ two_B;              // 2^B for消息编码
};
```

### CSKeyPair - 密钥对
```cpp
struct CSKeyPair {
    ZZ x;           // 私钥
    ZZ pk;          // 公钥 = g^x mod N^(zeta+1)
    uint32_t index; // 密钥索引
};
```

### CSCommitKey - 承诺密钥
```cpp
struct CSCommitKey {
    std::vector<ZZ> g;  // [g1, g2, ..., g_dim]
    ZZ h;               // 随机数生成元
};
```

## 快速开始

### 1. 初始化系统
```cpp
#include "cs_context.hpp"
using namespace PIS_CA;

// 创建上下文：3个密钥对，8维承诺
SystemParams params(3, 8);
CSContext context(params);

// 验证初始化
assert(context.isInitialized());
assert(context.getKeyCount() == 3);
```

### 2. 加密/解密
```cpp
// 准备消息向量
MessageVector messages = {ZZ(100), ZZ(200), ZZ(300), ZZ(400)};

// 使用第0个密钥对加密
CSCiphertext ct = context.encrypt(0, messages);

// 解密
MessageVector decrypted = context.decrypt(0, ct);
// decrypted == [100, 200, 300, 400]
```

### 3. 承诺操作
```cpp
// 8维消息向量
MessageVector messages;
for (int i = 0; i < 8; ++i) {
    messages.push_back(ZZ(i * 100));
}

// 创建承诺
CSCommitment com = context.commit(messages);

// 验证承诺
bool valid = context.verifyCommitment(com, messages, com.r);
```

### 4. 同态运算
```cpp
// 密文同态加法
CSCiphertext ct1 = context.encrypt(0, {ZZ(100), ZZ(200)});
CSCiphertext ct2 = context.encrypt(0, {ZZ(50), ZZ(100)});
CSCiphertext ct_add = context.homoAdd(ct1, ct2);
// 解密结果: [150, 300]

// 密文标量乘法
CSCiphertext ct_mul = context.scalarMul(ct1, ZZ(3));
// 解密结果: [300, 600]
```

## 构建指南

### 依赖项
- C++17 兼容编译器
- [NTL](https://libntl.org/) - 数论库
- OpenSSL - 哈希函数
- CMake 3.14+

### Windows构建
```powershell
# 创建构建目录
mkdir build
cd build

# 配置 (调整NTL路径)
cmake .. -DNTL_INCLUDE_DIR="C:\path\to\ntl\include" `
         -DNTL_LIBRARY="C:\path\to\ntl\lib\ntl.lib"

# 构建
cmake --build . --config Release

# 运行测试
Release\test_cs_system.exe
```

### Linux/macOS构建
```bash
mkdir build && cd build
cmake ..
make -j4
./test_cs_system
```

## 与原架构对比

| 特性 | 原架构 | 重构架构 |
|------|--------|----------|
| 生成元 | 每次密钥生成独立选择g' | **统一g，所有密钥共享** |
| 密钥对 | 单密钥对 | **支持多密钥对(keyCount参数)** |
| 承诺维度 | 固定维度 | **可配置维度(commitDimension参数)** |
| 密钥管理 | 分散管理 | **CSContext统一管理** |
| 扩展性 | 静态配置 | **动态扩展(addKeyPair, extendDimension)** |
| 接口 | 底层函数调用 | **面向对象的高层API** |

## 迁移指南

### 从旧代码迁移

**旧代码:**
```cpp
_CS::_public_key pk;
_CS::_secret_key sk;
_CS::_commit_key ck;
_CS::_setup(pk);
_CS::_key_generation(pk, sk, ck);
```

**新代码:**
```cpp
SystemParams params(1, 4);  // 1 key pair, 4-dim commitment
CSContext context(params);   // Automatic setup + keygen
const CSKeyPair& kp = context.getKeyPair(0);
```

**旧加密代码:**
```cpp
_CS::_ciphertext c;
ZZ r;
_encrypt(pk, message, r, c);
```

**新加密代码:**
```cpp
CSCiphertext ct = context.encrypt(0, message);
```

## 高级功能

### 动态添加密钥对
```cpp
// 初始2个密钥对
SystemParams params(2, 4);
CSContext context(params);

// 运行时添加第3个
context.addKeyPair();
// 现在有3个密钥对
```

### 扩展承诺维度
```cpp
// 初始4维
SystemParams params(1, 4);
CSContext context(params);

// 扩展到12维
context.extendCommitDimension(12);
// 现在可以承诺12维向量
```

### 多密钥加密
```cpp
// 同一消息用不同密钥加密
MessageVector msg = {ZZ(123), ZZ(456)};

CSCiphertext ct0 = context.encrypt(0, msg);  // 用key_0
CSCiphertext ct1 = context.encrypt(1, msg);  // 用key_1
CSCiphertext ct2 = context.encrypt(2, msg);  // 用key_2

// 各自只能用自己的密钥解密
MessageVector d0 = context.decrypt(0, ct0);  // OK
// context.decrypt(1, ct0);  // 失败!
```

## 许可证

MIT License (与原项目一致)
