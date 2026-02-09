# TLS 握手演示项目

这是一个用于演示TLS（Transport Layer Security）握手过程的Java项目，实现了**真实的客户端-服务器网络通信**，完整展示了TLS握手的7个阶段。

## 📋 项目概述

本项目通过Java Socket编程实现了真实的网络通信，完整演示了TLS握手的各个关键阶段：

1. **Client Hello & Server Hello** - 协商加密算法，交换随机数
2. **Server Certificate** - 服务器出示数字证书
3. **Certificate Verification** - 客户端验证CA签名
4. **Key Exchange** - Pre-Master Secret的加密交换（RSA方式）
5. **Session Key Generation** - 生成会话密钥
6. **Change Cipher Spec** - 切换到加密模式
7. **Encrypted Communication** - 使用会话密钥进行对称加密通信

## ✨ 核心特性

### 🌐 真实网络通信
- **客户端-服务器架构**：使用Java Socket API实现
- **多线程支持**：服务器支持多客户端同时连接
- **跨网络通信**：支持两台电脑通过网络通信
- **中英双语显示**：所有输出信息均为中英双语

### 🔐 完整TLS握手流程
- **7个阶段完整实现**：从协议协商到加密通信
- **密码学算法实现**：RSA、AES-GCM、数字签名
- **工具类封装**：CryptoUtils封装所有密码学操作

### 📦 模块化设计
- **网络通信模块**：TLSServer.java、TLSClient.java
- **密码学工具类**：CryptoUtils.java
- **演示模块**：保留原有单机演示模块作为参考

## 🚀 快速开始

### 环境要求

- Java 8 或更高版本
- 支持Java加密扩展（JCE）

### 编译项目

```bash
# Windows
compile.bat

# Linux/Mac
javac -d out -encoding UTF-8 *.java
```

### 运行演示

#### 方式1：单机演示（两个终端窗口）

**终端1 - 启动服务器：**
```bash
# Windows
run_server.bat

# Linux/Mac
cd out
java tls.demo.TLSServer
```

**终端2 - 启动客户端：**
```bash
# Windows
run_client.bat

# Linux/Mac
cd out
java tls.demo.TLSClient
```

#### 方式2：两台电脑演示（网络通信）

**服务器电脑：**
1. 运行 `compile.bat` 编译项目
2. 运行 `run_server.bat` 启动服务器
3. 记录服务器IP地址（如：192.168.1.100）

**客户端电脑：**
1. 修改 `TLSClient.java` 第24行：
   ```java
   private static final String SERVER_HOST = "192.168.1.100"; // 改为服务器IP
   ```
2. 运行 `compile.bat` 重新编译
3. 运行 `run_client.bat` 启动客户端

## 📚 代码结构

```
crypto_teamwork/
├── CryptoUtils.java              # 密码学工具类（封装所有密码学操作）
├── TLSServer.java                # 服务器端程序（网络通信+握手流程）
├── TLSClient.java                # 客户端程序（网络通信+握手流程）
│
├── KeyExchangeDemo.java          # RSA密钥交换演示（保留作为参考）
├── SignatureVerify.java          # 证书验证演示（保留作为参考）
├── CipherSuite.java              # AES-GCM加密演示（保留作为参考）
└── TLSHandshakeSimulator.java    # 完整握手流程模拟（保留作为参考）
```

## 🎯 核心演示内容

### 1. 网络通信模块

#### TLSServer.java - 服务器端
- 监听客户端连接（端口8888）
- 执行完整的TLS握手流程（7个阶段）
- 处理加密通信
- 支持多客户端连接（多线程）

#### TLSClient.java - 客户端
- 连接到服务器
- 执行完整的TLS握手流程（7个阶段）
- 发送和接收加密消息
- 交互式输入

### 2. 密码学工具类（CryptoUtils.java）

封装所有密码学操作，提供简单接口：

#### RSA密钥交换
- `generateRSAKeyPair()` - 生成RSA密钥对
- `generatePMS()` - 生成Pre-Master Secret
- `encryptPMS()` - 加密PMS
- `decryptPMS()` - 解密PMS
- `generateSessionKey()` - 生成会话密钥

#### 数字证书
- `generateCAKeyPair()` - 生成CA密钥对
- `signCertificate()` - 对证书签名
- `verifyCertificate()` - 验证证书签名

#### AES-GCM加密
- `deriveAESKey()` - 派生AES密钥
- `encrypt()` - AES-GCM加密
- `decrypt()` - AES-GCM解密

### 3. 演示模块（保留作为参考）

- **KeyExchangeDemo.java** - RSA密钥交换演示
- **SignatureVerify.java** - CA签名验证演示
- **CipherSuite.java** - AES-GCM对称加密演示
- **TLSHandshakeSimulator.java** - 完整握手流程模拟

## 🔄 TLS握手流程（7个阶段）

### 阶段1：Client Hello & Server Hello
- 协商TLS版本和加密算法
- 交换随机数 R1 和 R2（各32字节）

### 阶段2：Server Certificate
- 服务器发送数字证书
- 包含服务器公钥和CA签名

### 阶段3：Certificate Verification
- 客户端验证证书
- 检查CA签名

### 阶段4：Key Exchange
- 客户端生成Pre-Master Secret (PMS)
- 使用服务器公钥加密PMS
- 服务器使用私钥解密PMS

### 阶段5：Session Key Generation
- 双方使用 R1 + R2 + PMS 生成会话密钥
- 使用SHA-256算法

### 阶段6：Change Cipher Spec
- 双方切换到加密模式
- 握手完成

### 阶段7：Encrypted Communication
- 使用AES-256-GCM加密通信
- 双向加密数据传输

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

## 🎓 技术实现亮点

### 1. Socket网络编程
- 服务器：`ServerSocket`监听端口8888
- 客户端：`Socket`连接到服务器
- 数据流：`DataInputStream`和`DataOutputStream`

### 2. 多线程处理
- 服务器为每个客户端创建新线程
- 支持多客户端同时连接
- 线程安全的消息处理

### 3. 消息协议设计
- 使用分隔符`|||`避免冲突
- Base64编码传输二进制数据
- 清晰的消息类型标识

### 4. 错误处理
- 连接异常处理
- 消息格式验证
- 证书验证失败处理
- 优雅的连接关闭

## 📖 演示建议

### 演示顺序

1. **网络通信演示** - 先展示完整的握手流程
2. **密码学工具类** - 介绍工具类设计
3. **加密通信演示** - 展示实际数据加密传输
4. **技术实现亮点** - 强调后端能力

### 重点讲解

1. **网络编程** - Socket编程、多线程处理
2. **完整握手流程** - 7个阶段的详细过程
3. **密码学应用** - RSA、AES-GCM、数字签名
4. **实际应用场景** - 加密数据传输

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

1. 本项目为**教学演示**目的，实现了完整的TLS握手流程
2. 实际TLS使用PRF而非SHA-256生成会话密钥
3. 实际证书验证包含更多检查（如OCSP、CRL等）
4. 生产环境应使用TLS 1.3和ECDHE，而非RSA密钥交换
5. 网络通信需要确保防火墙允许端口8888

## 📄 许可证

本项目仅用于教育和演示目的。

## 👨‍💻 作者

NTU学生 - 密码学课程演示项目

---

**提示：** 运行代码时，请确保理解每个步骤的密码学原理和网络通信机制，这样才能在演示时向听众清晰地解释TLS握手的安全机制和实现细节。
