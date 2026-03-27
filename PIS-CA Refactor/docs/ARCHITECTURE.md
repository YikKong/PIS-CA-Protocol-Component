# PIS-CA Refactored Architecture Design

## 1. 设计目标

基于用户需求，重构后的架构实现以下核心特性：
- **统一生成元g**: 所有密钥对共享同一个生成元
- **多密钥对支持**: 通过参数控制密钥对数量
- **可扩展承诺系统**: 通过参数控制承诺维度，支持动态扩展

## 2. 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                     CSContext (统一管理接口)                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   CSPublicParams │  │  CSKeyPair[]   │  │  CSCommitKey   │  │
│  │   (统一公共参数)  │  │  (多密钥对集合) │  │  (承诺密钥)    │  │
│  │                  │  │                 │  │                │  │
│  │  N, N', g, T    │  │ [(x₀,pk₀),      │  │  g[0..dim-1]   │  │
│  │  N^zeta         │  │  (x₁,pk₁),      │  │  h             │  │
│  │                 │  │  ...]           │  │                │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      核心算法层                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ CSEncryption    │  │CSCommitmentScheme│  │   CSUtils      │  │
│  │ 加密/解密/同态   │  │  承诺/验证/同态  │  │ 工具函数       │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 3. 核心数据结构

### 3.1 SystemParams - 系统配置
```cpp
struct SystemParams {
    // 系统级常量 (security parameters)
    static constexpr uint32_t PRIME_BITS = 768;
    static constexpr uint32_t ZETA = 2;
    static constexpr uint32_t B_BITS = 768;
    
    // 用户可配置参数
    uint32_t keyCount;        // 密钥对数量 (默认: 1)
    uint32_t commitDimension; // 承诺维度 (默认: 4)
};
```

### 3.2 CSPublicParams - 公共参数 (共享)
```cpp
struct CSPublicParams {
    // RSA模数相关
    ZZ N;           // p * q (safe primes)
    ZZ N_prime;     // ((p-1)/2) * ((q-1)/2)
    ZZ N_zeta;      // N^zeta
    ZZ N_zeta_1;    // N^(zeta+1)
    
    // 核心生成元 (★所有密钥共享★)
    ZZ g;           // 统一生成元
    ZZ T;           // (1 + N) mod N^(zeta+1)
    ZZ two_B;       // 2^B for消息编码
};
```

### 3.3 CSKeyPair - 密钥对 (多个)
```cpp
struct CSKeyPair {
    ZZ x;           // 私钥: 随机选择
    ZZ pk;          // 公钥: g^x mod N^(zeta+1)
    uint32_t index; // 在密钥集合中的索引
};
```

**关键设计**: 所有 `pk_i = g^x_i` 使用相同的 `g`。

### 3.4 CSCommitKey - 承诺密钥 (可扩展)
```cpp
struct CSCommitKey {
    std::vector<ZZ> g;  // [g1, g2, ..., g_dim]
    ZZ h;               // 随机数生成元
};
```

**关键设计**: `g` 向量长度由 `commitDimension` 参数控制，支持动态扩展。

## 4. 算法流程

### 4.1 系统初始化 (setup)

```
Algorithm: InitializeSystem(params)
─────────────────────────────────
Input: SystemParams (keyCount, commitDimension)
Output: Initialized context with all parameters

1. Generate safe primes: p, q
2. Compute:
   - N = p * q
   - N' = ((p-1)/2)*((q-1)/2)
   - N^zeta, N^(zeta+1)
   - T = (1+N) mod N^(zeta+1)

3. Select unified generator g:
   repeat:
      g' ← random(2*PRIME_BITS)
   until GCD(g', N^(zeta+1)) == 1
   g = (g')^(2*N^zeta) mod N^(zeta+1)

4. Generate keyCount key pairs:
   for i = 0 to keyCount-1:
      x_i ← random(2*PRIME_BITS)
      pk_i = g^x_i mod N^(zeta+1)
      keyPairs[i] = (x_i, pk_i)

5. Generate commitment key:
   for i = 0 to commitDimension-1:
      repeat:
         g_i ← random(2*PRIME_BITS)
      until g_i^N' mod N == 1
   repeat:
      h ← random(2*PRIME_BITS)
   until h^N' mod N == 1

6. Return context with all components
```

### 4.2 加密流程

```
Algorithm: Encrypt(pp, keyPair, message)
───────────────────────────────────────
Input:  CSPublicParams pp
        CSKeyPair keyPair (x, pk)
        MessageVector message [m1, m2, ..., ms]
Output: CSCiphertext (u, e)

1. Encode message vector:
   m = Σ(m_i * (2^B)^i)  for i = 0 to s-1

2. Generate randomness:
   r ← random(2*PRIME_BITS)

3. Compute ciphertext:
   u = g^r mod N^(zeta+1)
   e = pk^r * (1+N)^m mod N^(zeta+1)
      = g^(x*r) * T^m mod N^(zeta+1)

4. Return (u, e)
```

### 4.3 解密流程

```
Algorithm: Decrypt(pp, secretKey, ciphertext)
────────────────────────────────────────────
Input:  CSPublicParams pp
        ZZ secretKey x
        CSCiphertext (u, e)
Output: MessageVector message

1. Recover (1+N)^m:
   T^m = e / (u^x) mod N^(zeta+1)
       = e * u^(-x) mod N^(zeta+1)

2. Decode m from (1+N)^m using DLog:
   m = DLog_N(T^m)
   // L((1+N)^j) = ((1+N)^j - 1) / N = j
   // For zeta > 1, use iterative decoding

3. Decode message vector:
   for i = s-1 down to 0:
      m_i = m / (2^B)^i
      m = m - m_i * (2^B)^i

4. Return [m_0, m_1, ..., m_{s-1}]
```

### 4.4 承诺生成

```
Algorithm: Commit(pp, commitKey, messages, r)
──────────────────────────────────────────
Input:  CSPublicParams pp
        CSCommitKey commitKey
        MessageVector messages [m1, ..., mk] (k ≤ dimension)
        ZZ r (randomness)
Output: CSCommitment com

1. Compute:
   com = h^r * Π(g[i]^m[i]) mod N^2
       = h^r * g[0]^m[0] * g[1]^m[1] * ... mod N^2

2. Return com
```

## 5. 同态运算支持

### 5.1 密文同态运算

| 操作 | 公式 | 结果含义 |
|------|------|----------|
| 加法 | c1 + c2 = (u1*u2, e1*e2) | 加密(m1 + m2) |
| 减法 | c1 - c2 = (u1/u2, e1/e2) | 加密(m1 - m2) |
| 标量乘 | k * c = (u^k, e^k) | 加密(k * m) |

### 5.2 承诺同态运算

| 操作 | 公式 | 结果含义 |
|------|------|----------|
| 加法 | com1 + com2 = com1 * com2 mod N^2 | 承诺(m1+m2, r1+r2) |
| 标量乘 | k * com = com^k mod N^2 | 承诺(k*m, k*r) |

## 6. 动态扩展机制

### 6.1 添加新密钥对

```cpp
void CSContext::addKeyPair() {
    // 使用相同的g生成新密钥对
    CSKeyPair kp(newIndex);
    kp.x = random(2*PRIME_BITS);
    kp.pk = g^x mod N^(zeta+1);  // ★使用统一的g★
    keyPairs.push_back(kp);
}
```

### 6.2 扩展承诺维度

```cpp
void CSContext::extendCommitDimension(uint32_t newDim) {
    // 生成额外的g[i]
    for i = currentDim to newDim-1:
        repeat:
            g_i ← random(2*PRIME_BITS)
        until g_i^N' mod N == 1
        commitKey.g.push_back(g_i);
}
```

## 7. 与原架构对比

| 特性 | 原架构 (Camenisch-shoup.h) | 重构架构 |
|------|---------------------------|----------|
| 生成元 | 每次调用`_key_generation`独立选择 `g'` | **全局统一g** |
| 密钥对 | 单密钥对 `(sk.x, pk._y)` | **多密钥对数组** |
| 承诺维度 | 固定 `const uint32_t s = 4` | **可配置维度** |
| 管理接口 | 分散的函数调用 | **统一CSContext** |
| 动态扩展 | 不支持 | **支持(addKeyPair, extendDimension)** |
| 安全性 | `768-bit` primes | 保持 `768-bit` |
| 消息编码 | 基于 `2^B` 编码 | 保持 `2^B` 编码 |

## 8. 使用模式

### 8.1 基础使用模式

```cpp
// 模式1: 单密钥对，标准承诺维度
SystemParams params;  // keyCount=1, commitDimension=4
CSContext ctx(params);

CSCiphertext ct = ctx.encrypt(0, message);
MessageVector decrypted = ctx.decrypt(0, ct);
```

### 8.2 多密钥使用模式

```cpp
// 模式2: 多密钥对场景
SystemParams params(5, 4);  // 5个密钥对
CSContext ctx(params);

// 用不同密钥加密
CSCiphertext ct0 = ctx.encrypt(0, msg);  // 密钥0
CSCiphertext ct1 = ctx.encrypt(1, msg);  // 密钥1

// 只有对应密钥能解密
auto d0 = ctx.decrypt(0, ct0);  // OK
// ctx.decrypt(1, ct0);         // 失败!
```

### 8.3 高维承诺使用模式

```cpp
// 模式3: 需要高维承诺
SystemParams params(1, 16);  // 16维承诺
CSContext ctx(params);

MessageVector msg(16);  // 16维消息
CSCommitment com = ctx.commit(msg);
```

### 8.4 动态扩展模式

```cpp
// 模式4: 运行时扩展
SystemParams params(1, 4);
CSContext ctx(params);

// 发现需要更多密钥
ctx.addKeyPair();  // 现在有2个密钥对

// 发现需要更高维度
ctx.extendCommitDimension(20);  // 扩展到20维
```

## 9. 文件组织

```
PIS-CA Refactor/
├── include/
│   ├── cs_types.hpp          # 核心类型定义
│   │   ├── SystemParams      # 系统参数
│   │   ├── CSPublicParams    # 公共参数
│   │   ├── CSKeyPair         # 密钥对
│   │   ├── CSCommitKey       # 承诺密钥
│   │   ├── CSCiphertext      # 密文
│   │   └── CSCommitment      # 承诺
│   │
│   ├── cs_encryption.hpp     # 加密算法接口
│   │   └── CSEncryption      # 静态方法类
│   │       ├── setup()
│   │       ├── generateKeyPairs()
│   │       ├── generateCommitKey()
│   │       ├── encrypt()
│   │       ├── decrypt()
│   │       ├── homomorphicAdd()
│   │       ├── homomorphicSub()
│   │       └── scalarMultiply()
│   │
│   ├── cs_commitment.hpp     # 承诺系统接口
│   │   ├── CSCommitmentScheme
│   │   │   ├── commit()
│   │   │   ├── verify()
│   │   │   ├── add()
│   │   │   └── scalarMul()
│   │   └── CSCommitmentUtils
│   │       ├── createCommitKey()
│   │       └── extendDimension()
│   │
│   ├── cs_context.hpp        # 统一上下文
│   │   └── CSContext
│   │       ├── initialize()
│   │       ├── getKeyPair()
│   │       ├── encrypt()/decrypt()
│   │       ├── commit()
│   │       ├── addKeyPair()
│   │       └── extendCommitDimension()
│   │
│   └── cs_utils.hpp          # 工具函数
│       ├── StringUtils
│       ├── HashUtils
│       ├── MathUtils
│       └── SerializationUtils
│
├── src/
│   ├── cs_encryption.cpp     # 加密实现
│   ├── cs_commitment.cpp     # 承诺实现
│   ├── cs_context.cpp        # 上下文实现
│   └── cs_utils.cpp          # 工具实现
│
├── tests/
│   └── test_cs_system.cpp   # 综合测试套件
│
├── examples/
│   └── simple_example.cpp    # 使用示例
│
├── CMakeLists.txt           # CMake配置
└── README.md                # 文档
```

## 10. 关键数学公式

### Camenisch-Shoup加密核心公式:

**密钥生成:**
- 私钥: `x ← Z_N'`
- 公钥: `pk = g^x mod N^(zeta+1)`

**加密:**
- 消息编码: `m = Σ(m_i * 2^(B*i))`
- 随机数: `r ← Z`
- 密文: `c = (u, e) = (g^r, pk^r * (1+N)^m)`

**解密:**
- 恢复: `(1+N)^m = e / u^x = e * u^(-x)`
- 解码: `m = DLog_N((1+N)^m)`

**同态加法:**
- `E(m1) + E(m2) = (u1*u2, e1*e2) = E(m1+m2)`

### Pedersen承诺核心公式:

**承诺:**
- `Com = h^r * Π(g_i^m_i) mod N^2`

**打开:**
- `(m_1, ..., m_k, r) → Com`

**同态加法:**
- `Com(m1, r1) * Com(m2, r2) = Com(m1+m2, r1+r2)`

## 11. 安全考虑

1. **安全素数**: 使用768-bit安全素数 (p, q 其中 p=2p'+1, q=2q'+1)
2. **随机数生成**: 使用NTL的RandomBits，避免弱随机数
3. **消息范围**: 通过B_BITS参数控制消息空间，防止溢出
4. **统一g的安全性**: 所有密钥共享同一g，基于相同的根信任

## 12. 性能考量

| 操作 | 复杂度 | 优化措施 |
|------|--------|----------|
| Setup | O(keyCount + commitDimension) | 预计算2^B幂次 |
| Encrypt | O(1) | 直接幂运算 |
| Decrypt | O(zeta * s) | 迭代DLog解码 |
| Commit | O(commitDimension) | 并行乘法链 |
| HomoAdd | O(1) | 单次模乘 |

## 13. 扩展建议

1. **并行化**: 多密钥生成和承诺生成可并行
2. **预计算**: 预计算g的幂次表加速加密
3. **批处理**: 支持批量加密/解密接口
4. **零知识证明**: 集成加密正确性证明
