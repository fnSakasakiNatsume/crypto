# TLS 握手演示项目

这是一个用于演示TLS（Transport Layer Security）握手过程的Java项目，特别适合用于学术演示和技术讲解。

## 📋 项目概述

本项目通过Java代码完整模拟了TLS握手的各个关键阶段，包括：

1. **Client Hello & Server Hello** - 协商加密算法，交换随机数
2. **Server Certificate** - 服务器出示数字证书
3. **Certificate Verification** - 客户端验证CA签名
4. **Key Exchange** - Pre-Master Secret的加密交换（RSA方式）
5. **Session Key Generation** - 生成会话密钥
6. **Encrypted Communication** - 使用会话密钥进行对称加密通信

## 🎯 核心演示内容

### 1. 密钥交换（KeyExchangeDemo.java）

演示RSA密钥交换的核心过程：

- **客户端生成Pre-Master Secret (PMS)**
  - 48字节随机数，包含TLS版本号和随机数据
  
- **客户端加密PMS**
  - 使用服务器公钥：`C ≡ PMS^e (mod n)`
  - 只有服务器拥有私钥，才能解密
  
- **服务器解密PMS**
  - 使用私钥：`PMS ≡ C^d (mod n)`
  - 证明只有服务器能获得PMS

- **生成会话密钥**
  - 使用PRF（伪随机函数）结合R1, R2, PMS
  - 双方生成相同的对称密钥

### 2. 对称加密（CipherSuite.java）

演示使用会话密钥进行实际数据加密：

- **AES-256-GCM加密**
  - 提供加密和认证（Authenticated Encryption）
  - 防止数据篡改和重放攻击
  
- **加密HTTP报文**
  - 模拟实际TLS通信中的数据加密过程
  - 展示IV（初始化向量）的使用

### 3. 数字证书验证（SignatureVerify.java）

演示CA签名验证机制，防止中间人攻击：

- **CA签名过程**
  - CA使用私钥对证书信息进行签名
  - 签名 = `Sign(Hash(证书内容), CA私钥)`
  
- **客户端验证**
  - 使用CA公钥验证签名
  - 验证 = `Verify(签名, Hash(证书内容), CA公钥)`
  
- **中间人攻击防护**
  - 攻击者无法伪造CA签名（没有CA私钥）
  - 即使截获通信，也无法冒充合法服务器

### 4. 完整握手流程（TLSHandshakeSimulator.java）

整合所有模块，演示完整的TLS握手过程，包括：

- 7个阶段的完整流程
- TLS 1.3的改进特性
- 前向安全性（Forward Secrecy）原理
- Java后端开发实践

## 🚀 快速开始

### 环境要求

- Java 8 或更高版本
- 支持Java加密扩展（JCE）

### 编译和运行

```bash
# 编译所有Java文件
javac -d . *.java

# 运行完整握手演示
java tls.demo.TLSHandshakeSimulator

# 或运行单个模块演示
java tls.demo.KeyExchangeDemo      # 密钥交换演示
java tls.demo.CipherSuite          # 对称加密演示
java tls.demo.SignatureVerify      # 证书验证演示
```

## 📚 代码结构

```
.
├── KeyExchangeDemo.java          # RSA密钥交换演示
├── CipherSuite.java              # AES-GCM对称加密演示
├── SignatureVerify.java          # CA签名验证演示
├── TLSHandshakeSimulator.java    # 完整握手流程模拟器
└── README.md                     # 项目说明文档
```

## 🔐 核心密码学概念

### RSA密钥交换

**加密公式：**
```
C ≡ M^e (mod n)
```
- `M`: Pre-Master Secret（明文）
- `e`: 公钥指数（通常为65537）
- `n`: RSA模数（2048位）
- `C`: 密文

**解密公式：**
```
M ≡ C^d (mod n)
```
- `d`: 私钥指数（只有服务器知道）
- 安全性：只有拥有私钥`d`的服务器才能解密

### 会话密钥生成

实际TLS使用PRF（伪随机函数）：
```
Session Key = PRF(PMS, "master secret", R1 + R2)
```

本项目使用SHA-256作为简化演示：
```
Session Key = SHA-256(R1 || R2 || PMS)
```

### 数字签名

**签名过程：**
```
Signature = RSA_Encrypt(SHA-256(Certificate), CA_PrivateKey)
```

**验证过程：**
```
Hash = SHA-256(Certificate)
Verify = RSA_Decrypt(Signature, CA_PublicKey) == Hash
```

## 🎓 扩展话题

### TLS 1.3 改进

1. **强制使用ECDHE**
   - 删除RSA密钥交换
   - 提供前向安全性

2. **0-RTT握手**
   - 利用Session Ticket实现快速重连
   - 第二次连接无需完整握手

3. **更快的握手速度**
   - 减少往返次数（从2次减少到1次）
   - 更少的加密操作

### 前向安全性（Forward Secrecy）

**问题：** 如果服务器私钥泄露，历史通信是否安全？

- **RSA密钥交换：** ✗ 没有前向安全性
  - 所有会话的PMS都用同一个服务器公钥加密
  - 私钥泄露后，所有历史通信都能被解密

- **ECDHE/DHE：** ✓ 提供前向安全性
  - 每次握手都生成新的临时密钥对
  - 会话密钥由临时密钥计算，不依赖服务器长期私钥
  - 即使服务器长期私钥泄露，历史通信仍安全

### Java后端开发实践

#### Spring Boot SSL配置

```properties
server.ssl.key-store=classpath:keystore.jks
server.ssl.key-store-password=changeit
server.ssl.key-store-type=JKS
server.ssl.key-alias=tomcat
server.port=8443
```

#### 常见错误处理

**SSLHandshakeException** 可能原因：
- 证书过期
- 证书不被信任（不在cacerts中）
- 证书域名不匹配
- 证书链不完整

**解决方法：**
```bash
# 查看cacerts中的证书
keytool -list -keystore $JAVA_HOME/jre/lib/security/cacerts

# 导入证书
keytool -import -alias myca -file ca.crt -keystore cacerts

# 生成自签名证书
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -keystore keystore.jks
```

#### Java信任存储（cacerts）

- **位置：** `$JAVA_HOME/jre/lib/security/cacerts`
- **默认密码：** `changeit`
- **内容：** 所有受信任的CA根证书
- **重要性：** 这是Java信任所有合法证书的来源

## 📖 演示建议

### 演示顺序

1. **TLSHandshakeSimulator** - 先展示完整流程，建立整体概念
2. **KeyExchangeDemo** - 深入讲解密钥交换的数学原理
3. **SignatureVerify** - 解释证书验证和MITM防护
4. **CipherSuite** - 展示实际数据加密过程

### 重点讲解

1. **数学公式** - 强调RSA加密/解密的数学原理
2. **安全性证明** - 解释为什么只有服务器能解密PMS
3. **中间人攻击** - 演示CA签名如何防止MITM
4. **前向安全性** - 对比RSA和ECDHE的区别

## 🔍 技术细节

### 使用的加密算法

- **非对称加密：** RSA 2048-bit
- **对称加密：** AES-256-GCM
- **哈希算法：** SHA-256
- **签名算法：** SHA256withRSA

### 密钥长度

- **RSA密钥：** 2048 bits
- **AES密钥：** 256 bits
- **Pre-Master Secret：** 48 bytes
- **Client/Server Random：** 32 bytes each

## 📝 注意事项

1. 本项目为**教学演示**目的，简化了部分实现细节
2. 实际TLS使用PRF而非SHA-256生成会话密钥
3. 实际证书验证包含更多检查（如OCSP、CRL等）
4. 生产环境应使用TLS 1.3和ECDHE，而非RSA密钥交换

## 📄 许可证

本项目仅用于教育和演示目的。

## 👨‍💻 作者

NTU学生 - 密码学课程演示项目

---

**提示：** 运行代码时，请确保理解每个步骤的密码学原理，这样才能在演示时向听众清晰地解释TLS握手的安全机制。
