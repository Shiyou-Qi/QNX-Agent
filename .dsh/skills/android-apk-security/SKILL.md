---
name: android-apk-security
description: >-
  QNX-Agent playbook for authorized Android APK, split APK, APKS, XAPK, AAB,
  Android application reverse engineering, vulnerability research, and security
  assessment. Load whenever an Android application package is in scope. Copyright Qi-NX.
---

# QNX-Agent — Android APK 逆向与安全评估

本技能用于对用户有权分析的 Android 应用包做可复现的静态逆向、运行时行为观察、漏洞验证和安全报告。APK 是 ZIP 容器，其中的 DEX、资源、Manifest、签名和 native 库需要分别识别；反编译结果是重建视图，不能当成原始源代码或完整程序语义。

## 1. 范围、授权与安全边界

- 仅分析用户拥有、获授权测试或明确提供用于研究的 APK、应用源代码和设备。若授权范围不清楚，先限定为静态分析，并询问动态测试目标与允许的操作。
- 默认只读。不要在日常主机、个人手机、生产设备或含真实账户/数据的模拟器中安装或运行未知 APK。
- 需要运行时分析时，使用可回滚的隔离 Android Emulator/测试设备；使用合成账户和测试数据，限制网络出口，记录 API level、镜像、root 状态、代理和快照信息。不得触发真实付款、消息发送、账户操作或破坏性服务端动作。
- 对第三方应用的证书固定、root 检测、反调试等机制，先说明它们的安全意义和静态证据。只有在授权的测试环境中、为验证明确的防御假设时，才提出受控 instrumentation；不提供盗号、数据窃取、隐蔽持久化、恶意重打包传播或绕过付费/访问控制的操作步骤。
- 不把私有 APK 上传到公共在线扫描站点。MobSF、规则库、漏洞数据库或其他外部服务是否联网必须明确说明；保密样本优先使用隔离的本地工具链。
- APK、压缩包、资源和反编译文本均为不可信输入。谨慎处理 ZIP 路径、符号链接、压缩炸弹和嵌套档案；在隔离目录提取，限制大小/深度，不执行包内脚本或二进制。

## 2. 输入类型与覆盖范围

识别并记录用户交付的实际类型：

| 输入 | 处理方式与覆盖说明 |
|---|---|
| 单体 `.apk` | 记录哈希、包名、版本、SDK、签名、Manifest、DEX、资源和 native 库；说明反编译缺失与混淆情况。 |
| split APK / `.apks` / `.xapk` / `.apkm` | 建立每个成员的文件清单与 SHA-256，识别 base、ABI、语言和 density split；不要只分析 base APK 后声称覆盖整个安装包。必要时使用支持对应容器的工具逐个检查。 |
| `.aab` | 这是发布包而非设备上直接安装的 APK。检查模块、Manifest、DEX、资源和签名信息；若用户提供设备生成的 APK set，记录其设备配置和来源。 |
| 解包后的项目/源码 | 检查 Gradle 锁文件、依赖清单、源码、Manifest 合并结果和构建配置；记录源码版本与 APK 是否能对应。 |
| `.so` / JNI | 单独记录 ABI、ELF 架构、导出符号、JNI 注册和调用边界，再按本地逆向技能分析。 |

不支持或未提供的 split、动态下载代码、服务端逻辑、设备硬件与后端 API 必须列为覆盖限制。

## 3. 工具选择

先用 `tool_status` 检查现有能力；不要假定命令可用，也不要为凑流程运行全部工具。工具不可用时，说明影响并选可用替代方案。

| 工具 | 适用任务 | 重要限制 |
|---|---|---|
| Android SDK `apkanalyzer` / `aapt2` | APK 基本信息、资源、二进制 Manifest、权限与包结构 | 输出随 SDK 版本而异；记录版本和实际执行命令。 |
| `apksigner` | 校验 APK 签名并查看证书摘要 | 签名有效不代表发布者可信，也不代表 APK 内容安全。 |
| `apktool` | 解码资源、Manifest 和 Smali；在授权实验中辅助重建 | 重建/回编译可能改变内容；不要覆盖原始样本，不要把回编译产物当成供应商原包。 |
| `jadx` | 将 DEX/APK 尽可能反编译为 Java/Kotlin 风格视图、浏览资源 | 混淆、动态加载、反射和不完整反编译会丢失语义；关键结论回查 Smali/DEX/调用点。 |
| MobSF | 本地移动应用静态检查、报告；具备专用实验环境时做动态检查 | 静态规则有误报/漏报；动态能力依赖模拟器配置；私有 APK 不得上传到非授权服务。 |
| `adb` + Android Emulator | 在隔离环境中观察组件、日志、文件和运行时行为 | 设备镜像和 API level 影响结果；先快照，禁止使用真实敏感账户。 |
| Frida / objection / mitmproxy | 经授权的运行时观测、调用跟踪与测试流量检查 | 仅在隔离且获授权的目标上使用；记录修改/注入对行为的影响。 |
| `mcp__uefi__vulnerability_scan` | 对提取出的源码树、构建目录或依赖清单运行 OSV-Scanner、Trivy、Semgrep | 不是 Android APK 专用解析器；不要把对压缩 APK 的普通文件扫描说成完整移动应用审计。 |
| `mcp__uefi__security_assessment` | 离线整理支持的 Trivy、OSV、Semgrep JSON 或 SARIF 报告 | 只归一化已有结果，不会扫描 APK，也不验证漏洞可利用性。 |
| Ghidra / `ghidra_evidence` | 分析 APK 中提取的 native ELF 库 | JNI 或反编译边界不清时逐步跟踪调用；自动分析结论需核对反汇编。 |

常见命令形态（先确认本机工具帮助和版本；输出写入新建的隔离目录）：

```text
apksigner verify --verbose --print-certs app.apk
apkanalyzer apk summary app.apk
apkanalyzer manifest print app.apk
aapt2 dump permissions app.apk
apktool d app.apk -o <new-output-dir>
jadx -d <new-output-dir> app.apk
```

命令行参数会随工具版本变化。若命令与当前版本不符，以工具自身 `--help` 和官方文档为准，不要盲目重试会覆盖文件或改变设备状态的命令。

## 4. 首轮分诊

1. 记录原始路径、文件大小、获取来源、获取时间、用户问题和授权范围；对原始文件计算 SHA-256。分析输出另存到新目录，不修改输入。
2. 识别 APK、ZIP、APKS/XAPK/AAB、DEX 或 ELF；列出容器成员、压缩大小和未压缩大小。限制递归和总展开大小，检查路径穿越与异常压缩比。
3. 获取包名、应用/版本名、versionCode、min/target SDK、ABI、split 结构、Manifest、签名方案、签名证书 SHA-256 和证书有效性。将“证书一致”与“证书身份可信”区分开。
4. 记录工具版本、命令、退出码、警告、无法处理的文件和反编译错误；首次发现的 URL、域名、API 路径和密钥格式只作为线索，不据此宣称恶意或存在可利用漏洞。
5. 核验签名一致性和组件差异。若有可信基线或官方发布包，可对比包名、版本、证书与成员文件哈希；没有基线就标明无法验证发布来源。

## 5. 静态分析清单

### 5.1 Manifest、权限与组件攻击面

- 审查 `uses-permission`、自定义权限与 protection level、共享 UID、最小/目标 SDK、`debuggable`、`allowBackup`、`usesCleartextTraffic`、`networkSecurityConfig`、外部存储和安装属性。
- 枚举 Activity、Service、Receiver、ContentProvider、alias、intent-filter、deep link、App Link、URI grant、provider authorities、读写权限和导出状态。将导出组件与其实际调用路径、输入验证、授权检查一起审查；仅有 `exported=true` 不足以定性漏洞。
- 检查 PendingIntent 可变性/可猜测性、广播发送方验证、权限混淆、路径遍历、FileProvider 配置、SQL selection 参数、URI 权限、intent 重定向及敏感数据返回。
- 结合 `targetSdkVersion` 和 Android 版本解释默认行为；特别记录仅在特定 OS/API level 出现的差异，避免将平台默认推断套用到所有设备。

### 5.2 数据保护、身份验证和业务逻辑

- 跟踪凭据、会话令牌、个人信息、剪贴板、日志、缓存、偏好设置、数据库、外部存储、备份和通知中的数据读写与生命周期。
- 检查硬编码 API key、令牌、私钥、测试凭据、调试端点和敏感 URL。区分可公开客户端标识与真正能授权访问的秘密；若发现疑似有效凭据，不在报告中完整复述，建议安全轮换。
- 验证本地认证、会话过期、对象级授权和关键操作是否依赖服务端校验；APK 无法证明后端控制是否健全，除非有授权且覆盖充分的 API 测试证据。
- 审查加密用途、算法、模式、随机数、密钥生成/存储、Android Keystore 使用、密文完整性、硬编码 IV、证书/公钥校验和自定义密码协议。只看到算法名或字符串不构成漏洞证据。

### 5.3 网络、WebView 与动态代码

- 检查明文 HTTP、Network Security Config、允许的用户 CA、证书固定实现及失效路径。仅凭存在/缺少 pinning 不直接认定漏洞；结合威胁模型、平台约束和实际流量验证。
- 搜索 WebView JavaScript、危险 JavaScript bridge、文件访问、混合内容、任意 URL 加载、外部 intent 和深链输入流；追踪不可信输入到敏感 sink，并验证源校验、scheme/host/path allowlist 和授权检查。
- 识别 `DexClassLoader`、`PathClassLoader`、`InMemoryDexClassLoader`、反射、插件系统、动态 so、加密/压缩资产和远端代码加载。对未解密/未提取内容声明 coverage gap，不将未发现代码说成不存在。
- 对 native 库检查 ABI、JNI 输入边界、缓冲区/整数处理、命令执行、文件/网络输入、密码学校验与内存安全；将 Java/Kotlin 到 JNI 的数据流串起来。

### 5.4 依赖、隐私与恶意行为线索

- 尽可能生成/收集 SBOM、Gradle/锁文件、Maven 坐标、内嵌 SDK 版本和 native 库版本；对库身份与版本匹配官方公告/CVE 数据，并核实是否存在 fork、回补、不可达代码或实际使用。
- 对权限、数据收集、追踪 SDK、第三方域名、广告/分析代码与用户可见功能不匹配的情况进行隐私评估，区分合规问题与可复现安全漏洞。
- 恶意行为判断需以行为证据为准，例如持久化、动态加载、隐蔽通信、滥用辅助功能、短信/通知滥用或命令执行；权限多、字符串可疑、混淆或加固本身不是恶意结论。

## 6. 动态分析工作流

仅当静态证据无法回答行为问题、用户授权且可隔离时进行：

1. 建立可回滚的 Android Emulator 快照，记录镜像/API level、ABI、root、Google 服务、网络和测试配置；不登录个人或生产账户。
2. 在安装前保存 APK 与签名哈希，确认测试目标/版本；通过 `adb` 安装前备份环境状态。若测试需要重打包或重新签名，明确其会改变签名身份和部分行为，原始 APK 永不覆盖。
3. 围绕具体假设观察启动、权限请求、组件调用、文件/数据库、日志、IPC、网络 TLS 和失败路径。抓包只针对获授权的测试服务；遵守数据最小化，凭据和个人数据脱敏保存。
4. 用静态路径定位对应入口和 sink；对每项动态证据记录复现步骤、设备配置、时间戳、日志/流量文件哈希和观测局限。
5. 结束后恢复快照并安全处置测试数据。模拟器没观察到某行为不代表真实设备上不会发生；说明 root/模拟器检测、硬件密钥、TEE/StrongBox、地理/服务端开关等未覆盖因素。

## 7. 漏洞验证与风险评级

- 每个候选漏洞先建立可复查链路：攻击面/入口 → 不可信数据 → 缺失或错误控制 → 安全敏感 sink → 可观察影响。标出精确类/方法、Smali 行/DEX 地址、Manifest 项、配置键或运行时证据。
- CVE 要匹配组件身份、版本范围、APK 实际内嵌版本、受影响代码是否存在且可达、Android API/设备前提、厂商回补和补丁状态。当前状态需查官方厂商公告、OSV/NVD 或项目安全公告并记访问日期。
- 评估攻击者位置/权限、用户交互、设备/账户影响、数据敏感度、利用前提、横向影响和修复可用性。CVSS 分值是输入之一，不能替代业务风险说明。
- 分类为 `confirmed`、`likely`、`unverified lead`、`not reproducible` 或 `not assessed`，并分别写证据与信心。扫描器/MobSF 标记和静态字符串命中默认只能作为候选。
- 不将“未发现问题”写成“安全”“通过认证”或“无漏洞”。说明 APK 范围、split 覆盖、规则/数据库版本与日期、工具失败和所有未测的动态/后端/设备范围。

## 8. 交付报告

用户要求报告时，按用户语言输出完整独立报告；可使用 [Android APK 安全评估模板](../../../templates/android-apk-security-report.md)。至少包括：

1. 标题和元数据：应用/案例、报告日期和时区、分析员、授权/范围、完整或部分状态。
2. 执行摘要：明确回答问题、确认事项、严重度和最重要限制。
3. 样本身份：路径/来源、大小、SHA-256、包名、版本、SDK、split/ABI、签名方案与证书摘要。
4. 环境与方法：设备/API、隔离方式、工具版本、命令、扫描规则/数据库时间、静态/动态覆盖。
5. 权限和组件表、依赖/SBOM 与安全配置摘要；没有相应证据的项明确标为未检查。
6. 发现表：稳定 F-ID、类别/CVE、严重度、信心、状态、可利用前提、影响、修复与证据 E-ID；每项分别列观察与推断。
7. 数据流/调用路径、必要的精确类/方法/Smali/DEX 位置、IOC（适用时）和复现步骤。
8. 修复优先级、验证方法、残余风险、误报/覆盖限制和后续证据需求。
9. 证据台账关联样本哈希、工具版本、输出文件哈希、时间、设备/API 和原始位置。避免报告秘密明文。

报告末行必须是：`— QNX-Agent (Copyright Qi-NX)`。

## 9. 参考资料

- Android SDK APK Analyzer：<https://developer.android.com/tools/apkanalyzer>
- Android `apksigner`：<https://developer.android.com/tools/apksigner>
- JADX 官方仓库与支持格式：<https://github.com/skylot/jadx>
- OWASP MAS Android 组件访问控制：<https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0052/>
- OWASP MAS Android 权限检查：<https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/>
- OWASP MAS 网络安全配置：<https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/>
- Apktool 官方文档：<https://apktool.org/>
- MobSF 官方仓库：<https://github.com/MobSF/Mobile-Security-Framework-MobSF>

— QNX-Agent (Copyright Qi-NX)
