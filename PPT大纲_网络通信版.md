# TLS握手演示项目 - 小组展示PPT大纲（网络通信版）

## 8分钟展示结构（含演示视频流程）

---

## 第1页：封面页

**标题：** TLS握手过程完整演示
**副标题：** 基于Java的网络通信实现
**信息：**

- 小组成员：Feng Ruhui   Zhao Jinghao
- 课程：SC6104密码学
- 日期：[展示日期]

---

## 第2页：项目概述（30秒）

**标题：** 项目简介

**内容要点：**

- **项目目标：** 实现真实的客户端-服务器网络通信，完整演示TLS握手的7个阶段
- **核心特性：**
  1. 真实的网络通信（Socket编程）
  2. 完整的TLS握手流程（7个阶段）
  3. 密码学算法实现（RSA、AES-GCM、数字签名）
  4. 加密数据传输（双向加密通信）

**目的：**

- 可视化TLS握手过程
- 展示网络编程能力
- 深入理解密码学原理
- 实际应用场景演示

---

## 第3页：系统架构（1分钟）

**标题：** 客户端-服务器架构

**架构图展示：**

```
┌─────────────────┐        网络通信        ┌─────────────────┐
│   TLS Client    │  ←────────────────→  │  TLS Server     │
│   (客户端程序)   │                       │  (服务器程序)   │
│                 │                       │                 │
│ 1. 发起连接      │  Client Hello ──────> │ 1. 监听连接     │
│ 2. 验证证书      │ <──── Server Hello   │ 2. 发送证书     │
│ 3. 密钥交换      │  Key Exchange ──────> │ 3. 接收PMS      │
│ 4. 加密通信      │  Encrypted Data ───> │ 4. 解密数据     │
└─────────────────┘                       └─────────────────┘
```

**技术栈：**

- **网络编程：** Java Socket API
- **多线程：** 服务器支持多客户端连接
- **密码学：** RSA、AES-GCM、SHA-256
- **工具封装：** CryptoUtils工具类

**演示方式：**

- 单机演示：两个终端窗口（localhost）
- 网络演示：两台电脑通过网络通信

---

## 第4页：握手流程演示（2.5分钟）- 重点

**标题：** TLS握手7个阶段完整演示

**演示视频流程示意：**

**运行命令：**

- 终端1：`run_server.bat`（启动服务器）
- 终端2：`run_client.bat`（启动客户端）

**完整流程展示：**

### 阶段1：Client Hello & Server Hello（30秒）

**客户端显示：**

```
[Phase 1] Sending Client Hello... / [阶段1] 发送 Client Hello...
Sent: Client Hello:TLS 1.2:AbCdEf123... / 发送: Client Hello:TLS 1.2:AbCdEf123...
  - TLS Version: 1.2
  - Cipher Suites: TLS_RSA_WITH_AES_256_GCM_SHA384
  - Client Random (R1): PT59H6L37KKkK...
```

**服务器显示：**

```
[Phase 1] Receiving Client Hello... / [阶段1] 接收 Client Hello...
Received: Client Hello:TLS 1.2:AbCdEf123... / 收到: Client Hello:TLS 1.2:AbCdEf123...

[Phase 1] Sending Server Hello... / [阶段1] 发送 Server Hello...
Sent: Server Hello:TLS 1.2:XyZ789... / 发送: Server Hello:TLS 1.2:XyZ789...
✓ Encryption algorithms and version negotiated / 双方已协商好加密算法和版本
✓ Random numbers R1 and R2 exchanged / 双方已交换随机数 R1 和 R2
```

**关键点：**

- 协议协商（TLS版本、加密套件）
- 随机数交换（R1和R2，各32字节）
- 网络消息传输

---

### 阶段2：Server Certificate（20秒）

**服务器显示：**

```
[Phase 2] Sending Server Certificate... / [阶段2] 发送 Server Certificate...
Certificate sent / 证书已发送
  - Subject: CN=localhost
  - Public Key: RSA 2048-bit
  - Signature Algorithm: SHA256withRSA
```

**客户端显示：**

```
[Phase 2] Receiving Server Certificate... / [阶段2] 接收 Server Certificate...
Certificate information: / 证书信息:
  - CN=localhost, O=Demo Server, C=US
  - Public Key: RSA 2048-bit
  - Signature Algorithm: SHA256withRSA
```

**关键点：**

- 数字证书结构
- 服务器公钥传输
- CA公钥传输（用于验证）

---

### 阶段3：Certificate Verification（20秒）

**客户端显示：**

```
[Phase 3] Verifying certificate... / [阶段3] 验证证书...
  1. Check if certificate is expired / 检查证书是否过期
  2. Check if certificate domain matches / 检查证书域名是否匹配
  3. Verify CA signature / 验证CA签名
✓ Certificate verified! Server identity trusted / 证书验证通过！服务器身份可信
```

**服务器显示：**

```
[Phase 3] Waiting for certificate verification... / [阶段3] 等待客户端验证证书...
✓ Certificate verified! Server identity trusted / 证书验证通过！服务器身份可信
```

**关键点：**

- CA签名验证机制
- 防止中间人攻击
- 身份认证过程

---

### 阶段4：Key Exchange（30秒）

**客户端显示：**

```
[Phase 4] Generating and encrypting Pre-Master Secret... / [阶段4] 生成并加密 Pre-Master Secret...
✓ Pre-Master Secret generated successfully / Pre-Master Secret生成成功
  - Length: 48 bytes / 长度: 48 bytes
  - First 2 bytes (version): 0x0303 / 前2字节（版本）: 0x0303

✓ Encrypted PMS using server public key / 使用服务器公钥加密PMS
  - Encryption algorithm: RSA/ECB/PKCS1Padding / 加密算法: RSA/ECB/PKCS1Padding
  - Original PMS length: 48 bytes / 原始PMS长度: 48 bytes
  - Encrypted length: 256 bytes / 加密后长度: 256 bytes
✓ Encrypted PMS sent / 加密的PMS已发送
```

**服务器显示：**

```
[Phase 4] Receiving encrypted Pre-Master Secret... / [阶段4] 接收加密的 Pre-Master Secret...
✓ PMS decrypted successfully / PMS解密成功
  - Decryption algorithm: RSA/ECB/PKCS1Padding / 解密算法: RSA/ECB/PKCS1Padding
  - PMS length: 48 bytes / PMS长度: 48 bytes
```

**关键点：**

- RSA加密/解密过程
- 数学原理：C ≡ PMS^e (mod n)
- 只有服务器能解密（拥有私钥）

---

### 阶段5：Session Key Generation（20秒）

**双方同时显示：**

```
[Phase 5] Generating session key... / [阶段5] 生成会话密钥...
✓ Session key generated / 会话密钥已生成
  - Input: R1 (Client Random) + R2 (Server Random) + PMS / 输入: R1 (Client Random) + R2 (Server Random) + PMS
  - Algorithm: SHA-256 / 算法: SHA-256
  - Session key length: 32 bytes (256 bits) / 会话密钥长度: 32 bytes (256 bits)
  - Session key (first 20 chars): K1j2L3m4N5o6P7q8R9s0... / 会话密钥 (前20字符): K1j2L3m4N5o6P7q8R9s0...
```

**关键点：**

- 密钥派生算法
- 双方生成相同的密钥
- 从非对称加密切换到对称加密

---

### 阶段6：Change Cipher Spec（10秒）

**双方显示：**

```
[Phase 6] Switching to encrypted mode... / [阶段6] 切换到加密模式...
Received: Change Cipher Spec / 收到: Change Cipher Spec
✓ Switched to encrypted mode / 已切换到加密模式
✓ Handshake complete! Both sides switched to encrypted communication / 握手完成！双方已切换到加密通信模式
```

**关键点：**

- 协议状态转换
- 握手完成标志

---

### 阶段7：Encrypted Communication（30秒）

**客户端显示：**

```
[Phase 7] Starting encrypted communication... / [阶段7] 开始加密通信...
Enter message to send to server (type 'quit' to exit): / 输入消息发送给服务器（输入 'quit' 退出）:

> hello how about the quiz
[Encrypted message sent] hello how about the quiz / [已发送加密消息] hello how about the quiz
  - Encryption algorithm: AES-256-GCM / 加密算法: AES-256-GCM
  - Original length: 24 bytes / 原始长度: 24 bytes
  - Ciphertext length: 40 bytes / 密文长度: 40 bytes

[Server reply] Server received: hello how about the quiz / [服务器回复] Server收到: hello how about the quiz
```

**服务器显示：**

```
[Phase 7] Starting encrypted communication... / [阶段7] 开始加密通信...
Received encrypted message: hello how about the quiz / 收到加密消息: hello how about the quiz
  - Encryption algorithm: AES-256-GCM / 加密算法: AES-256-GCM
  - Ciphertext length: 40 bytes / 密文长度: 40 bytes
Replied with encrypted message / 已回复加密消息
```

**关键点：**

- AES-GCM加密/解密
- 数据完整性验证
- 双向加密通信
- 实际应用场景

---

## 第5页：密码学工具封装（1分钟）

**标题：** CryptoUtils工具类设计

**设计理念：**

- 封装所有密码学操作
- 对外提供简单接口
- 隐藏实现细节
- 便于维护和扩展

**核心功能模块：**

### 1. RSA密钥交换

```java
generateRSAKeyPair()      // 生成RSA密钥对
generatePMS()            // 生成Pre-Master Secret
encryptPMS()             // 加密PMS
decryptPMS()             // 解密PMS
generateSessionKey()      // 生成会话密钥
```

### 2. 数字证书

```java
generateCAKeyPair()      // 生成CA密钥对
signCertificate()        // 对证书签名
verifyCertificate()      // 验证证书签名
```

### 3. AES-GCM加密

```java
deriveAESKey()           // 派生AES密钥
encrypt()                // AES-GCM加密
decrypt()                // AES-GCM解密
```

**优势：**

- ✓ 代码复用性高
- ✓ 易于测试和维护
- ✓ 密码学细节与业务逻辑分离
- ✓ 便于后续扩展（如支持TLS 1.3）

---

## 第6页：加密通信演示（1.5分钟）- 重点

**标题：** 实际加密数据传输

**演示场景：**

### 场景1：发送消息

**输入：** `hello how about the quiz`（24 bytes）

**加密过程：**

- 使用AES-256-GCM加密
- 生成随机IV（12 bytes）
- 加密数据 + 认证标签 = 40 bytes

**传输：**

- 密文（Base64编码）
- IV（Base64编码）
- 通过网络传输

**解密过程：**

- 服务器接收密文和IV
- 使用会话密钥解密
- 验证数据完整性（GCM自动验证）
- 恢复原始消息

### 场景2：数据完整性验证

**演示：**

- 如果密文被篡改，解密会失败
- GCM模式自动检测数据完整性
- 防止重放攻击（每次使用不同IV）

**关键数据对比：**

- 明文：24 bytes
- 密文：40 bytes（包含16字节认证标签）
- 加密开销：16 bytes（用于认证）

**安全性保障：**

- ✓ 数据机密性（AES加密）
- ✓ 数据完整性（GCM认证标签）
- ✓ 防止重放攻击（随机IV）

---

## 第7页：后端实现亮点（1分钟）

**标题：** 技术实现亮点

### 1. Socket网络编程

**实现：**

- 服务器：`ServerSocket`监听端口8888
- 客户端：`Socket`连接到服务器
- 数据流：`DataInputStream`和 `DataOutputStream`

**特点：**

- 可靠的TCP连接
- 支持跨网络通信
- 异常处理和错误恢复

### 2. 多线程处理

**实现：**

- 服务器为每个客户端创建新线程
- 支持多客户端同时连接
- 线程安全的消息处理

**代码示例：**

```java
new Thread(() -> {
    handleClient(clientSocket);
}).start();
```

### 3. 消息协议设计

**格式：**

- 使用分隔符 `|||`避免冲突
- Base64编码传输二进制数据
- 清晰的消息类型标识

**示例：**

```
Certificate|||证书信息|||服务器公钥|||CA公钥|||签名
Key Exchange:Base64(加密的PMS)
```

### 4. 错误处理

**机制：**

- 连接异常处理
- 消息格式验证
- 证书验证失败处理
- 优雅的连接关闭

---

## 第8页：项目文件结构（30秒）

**标题：** 代码组织

**核心文件：**

```
crypto_teamwork/
├── CryptoUtils.java          # 密码学工具类（封装所有密码学操作）
├── TLSServer.java            # 服务器端程序（网络通信+握手流程）
├── TLSClient.java            # 客户端程序（网络通信+握手流程）
│
├── KeyExchangeDemo.java      # RSA密钥交换演示（保留作为参考）
├── SignatureVerify.java      # 证书验证演示（保留作为参考）
├── CipherSuite.java          # AES-GCM加密演示（保留作为参考）
└── TLSHandshakeSimulator.java # 完整握手流程模拟（保留作为参考）
```

**运行脚本：**

- `compile.bat` - 编译所有Java文件
- `run_server.bat` - 运行服务器
- `run_client.bat` - 运行客户端
- `run_network_demo.bat` - 演示说明

**代码统计：**

- 网络通信：TLSServer.java (210行) + TLSClient.java (227行)
- 工具封装：CryptoUtils.java (178行)

---

## 第9页：个人贡献（30秒）

**标题：** 小组成员贡献

### 同学1（你的名字）

**负责模块：**

- CryptoUtils.java（178行）- 密码学工具类封装
- TLSServer.java（210行）- 服务器端实现

**核心贡献：**

1. 设计并实现密码学工具类，封装RSA、AES-GCM、数字签名等操作
2. 实现服务器端网络通信和TLS握手流程
3. 实现多线程客户端处理机制
4. 设计消息协议格式，解决证书信息中的冒号冲突问题

**掌握的技术：**

- 密码学算法封装和工具类设计
- Java Socket网络编程
- 多线程编程和并发处理
- 消息协议设计

---

### 同学2（朋友名字）

**负责模块：**

- TLSClient.java（227行）- 客户端实现
- 测试和调试

**核心贡献：**

1. 实现客户端网络通信和TLS握手流程
2. 实现交互式加密消息发送/接收
3. 实现证书验证逻辑（CA公钥验证）
4. 完成端到端测试，确保握手流程完整

**掌握的技术：**

- Java Socket客户端编程
- 交互式输入/输出处理
- 证书验证和CA信任机制
- 加密通信实现

---

## 第10页：总结与展望（30秒）

**标题：** 项目总结

**核心成果：**

- ✓ 实现了真实的客户端-服务器网络通信
- ✓ 完整演示了TLS握手的7个阶段
- ✓ 实现了所有核心密码学算法（RSA、AES-GCM、数字签名）
- ✓ 展示了加密数据传输的实际应用

**技术亮点：**

- 网络编程能力（Socket、多线程）
- 密码学算法实现和封装
- 完整的协议流程实现
- 错误处理和异常管理

**学习收获：**

- 深入理解TLS握手协议
- 掌握网络编程实践
- 理解密码学在实际应用中的作用
- 提升代码组织和架构设计能力

**致谢&QA**

---

## 演示视频录制建议

### 视频1：完整握手流程演示（1分钟）

**录制内容：**

1. 打开两个终端窗口
2. 终端1运行服务器：`run_server.bat`
3. 终端2运行客户端：`run_client.bat`
4. 完整展示7个阶段的握手过程
5. 重点标注：每个阶段的关键数据、网络消息传输

### 视频2：加密通信演示（0.5分钟）

**录制内容：**

1. 握手完成后，在客户端输入消息
2. 展示消息加密过程（明文→密文）
3. 展示服务器解密过程（密文→明文）
4. 展示双向加密通信
5. 重点标注：数据长度对比、加密算法信息

---

## 时间分配建议

| 页面           | 内容                    | 时间              |
| -------------- | ----------------------- | ----------------- |
| 第1页          | 封面                    | 5秒               |
| 第2页          | 项目概述                | 30秒              |
| 第3页          | 系统架构                | 1分钟             |
| 第4页          | 握手流程演示（含视频1） | 2.5分钟           |
| 第5页          | 密码学工具封装          | 1分钟             |
| 第6页          | 加密通信演示（含视频2） | 1.5分钟           |
| 第7页          | 后端实现亮点            | 1分钟             |
| 第8页          | 项目文件结构            | 30秒              |
| 第9页          | 个人贡献                | 30秒              |
| 第10页         | 总结                    | 30秒              |
| **总计** |                         | **约8分钟** |

---

## 演示技巧建议

1. **开场：** 简洁介绍项目，强调网络通信特性
2. **架构展示：** 用架构图快速建立整体概念
3. **握手演示：** 重点展示7个阶段的完整流程，强调网络消息传输
4. **加密通信：** 展示实际的数据加密传输，对比明文和密文长度
5. **技术亮点：** 强调网络编程、多线程、错误处理等后端能力
6. **总结：** 回顾核心要点，强调项目的实际应用价值

**注意事项：**

- 视频录制时确保两个终端窗口都清晰可见
- 重点标注网络消息传输和关键数据
- 控制语速，确保8分钟内完成所有内容
- 准备备用方案（如果网络演示出现问题，可以用单机演示）

---

## 可能的问题和回答

### Q1: "为什么选择实现网络通信而不是单机模拟？"

**A:** "我们想展示真实的网络编程能力，而不仅仅是密码学算法。网络通信更能体现TLS协议的实际应用场景，也展示了我们的Socket编程和多线程处理能力。"

### Q2: "如何保证网络通信的安全性？"

**A:** "我们实现了完整的TLS握手流程，包括证书验证、密钥交换、加密通信。所有数据都经过加密传输，使用AES-256-GCM提供加密和认证双重保护。"

### Q3: "如果网络断开会怎样？"

**A:** "我们实现了异常处理机制，网络断开时会捕获异常并优雅地关闭连接。服务器可以继续监听，等待新的客户端连接。"

### Q4: "支持多客户端连接吗？"

**A:** "是的，服务器使用多线程处理，每个客户端连接都会创建新线程，可以同时处理多个客户端。"

### Q5: "密码学算法是你们自己实现的吗？"

**A:** "我们使用了Java的加密库（JCE），但自己实现了完整的协议流程，包括密钥交换、证书验证、会话密钥生成等。所有密码学操作都封装在CryptoUtils工具类中。"

---

**提示：** 这个PPT大纲基于真实的网络通信功能，重点展示后端实现能力和完整的TLS握手流程。可以直接提供给Kimi生成PPT。
