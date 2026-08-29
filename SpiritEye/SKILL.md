---
name: spirit-eye
description: >
  灵眸·天鉴（SpiritEye）——AI 驱动的通用静态应用安全测试（SAST）技能，用于代码漏洞分析。
  SpiritEye is a general-purpose Static Application Security Testing (SAST) skill for code vulnerability analysis.
  触发场景：用户要求"分析代码漏洞"、"审查代码安全"、"查找安全缺陷"、"执行 SAST 扫描"、
  "检查代码中的[某类漏洞]"、"审计源代码"，或对任意语言/框架请求安全代码审查。
  覆盖 Web、API、认证授权、移动端、业务逻辑等 35 类漏洞。
metadata:
  version: "0.1.0"
  domain: application-security
  references: 35 vulnerability knowledge bases
---

# SAST 漏洞分析（灵眸·天鉴 SpiritEye）

## 目标

使用结构化的 Source→Sink 污点追踪、模式匹配与漏洞类专属检测规则，系统性地分析源代码中的安全漏洞。输出可落地的发现结果，包含严重性评级、受影响代码位置（文件+行号）与修复建议。

## 授权与合规边界

- **仅审计授权目标**：默认只审计用户明确有权测试 / 审查的源代码。对外部组织或个人代码的审计，需具备书面授权（渗透测试授权书、安全评估委托等）
- **只读分析**：本技能进行静态分析，不执行破坏性操作；渗透测试 payload 验证仅限已授权的靶场 / 测试环境（如 pikachu-master）
- **数据合规**：审计结果可能含敏感信息，报告须妥善保管；OSS 上传仅在用户配置凭证并明确要求时进行，凭证一律走环境变量
- **禁止滥用**：不得将本技能用于未授权入侵、规避安全防护或其他不当用途

## 覆盖范围

### 支持语言

本技能可审计以下语言，通过"通用漏洞类 + 语言适配检测规则 + 平台特有知识库"三层方式覆盖：

| 支持语言 | 审计方式 |
|---|---|
| **Java** | 通用 35 类漏洞 + Spring/Struts 等框架特定 Source/Sink 模式（反序列化链、JNDI、SpEL 等） |
| **Python** | 通用 35 类漏洞 + Django/Flask/FastAPI 等框架特定模式（pickle/yaml.load、模板注入等） |
| **JavaScript / TypeScript** | 通用 35 类漏洞 + Node.js/浏览器端特定模式（原型污染、NoSQL 注入等） |
| **PHP** | 通用 35 类漏洞 + `php_security.md` 平台特有知识库（eval/assert、allow_url_include 等） |
| **.NET** | 通用 35 类漏洞 + ASP.NET 框架特定模式（反序列化、视图注入等） |

### 漏洞覆盖

本技能覆盖以下 35 类漏洞。每一类都有独立的参考文档，按需加载：

| 类别 | 漏洞 |
|----------|----------------|
| **注入类（Injection）** | SQL 注入、XSS、SSTI、NoSQL 注入、GraphQL 注入、XXE、RCE / 命令注入、表达式语言注入 |
| **访问控制与认证（Access Control & Auth）** | IDOR、越权、认证/JWT、默认凭据、暴力破解、业务逻辑、HTTP 方法篡改、验证码滥用、会话固定 |
| **数据暴露与加密（Data Exposure & Crypto）** | 弱加密/弱哈希、信息泄露、不安全的 Cookie 属性、信任边界 |
| **服务端（Server-Side）** | SSRF、路径穿越/LFI/RFI、不安全反序列化、任意文件上传、JNDI 注入、竞态条件 |
| **协议与基础设施（Protocol & Infrastructure）** | CSRF、开放重定向、HTTP 请求走私/失步、拒绝服务、CVE 模式、供应链攻击（supply_chain） |
| **语言/平台（Language/Platform）** | PHP 安全、移动端安全（Android/iOS） |

> **说明**："语言/平台"类别仅收录**平台特有漏洞知识库**（PHP 安全、移动端安全）。Java、Python、JavaScript/TypeScript、.NET 的漏洞检测由上方 33 类通用漏洞知识库 + 各语言适配规则完成，并非仅能审计 PHP 与移动端。

---

## 工作流程

### 第 1 步：明确审计范围

确定：
- 目标：单个文件、目录、API 端点、模块或整个仓库
- 使用中的语言与框架
- 用户目标：快速扫描、深度审计、特定漏洞类型或完整报告

### 第 2 步：加载相关漏洞知识库

根据被审查的代码，从 `references/` 加载对应的参考文档：

```
references/sql_injection.md          — SQL / ORM 注入
references/xss.md                    — 跨站脚本
references/ssrf.md                   — 服务端请求伪造
references/rce.md                    — 远程代码执行
references/idor.md                   — 不安全的直接对象引用
references/authentication_jwt.md     — 认证缺陷、JWT 弱点
references/csrf.md                   — 跨站请求伪造
references/path_traversal_lfi_rfi.md — 路径穿越、LFI/RFI
references/ssti.md                   — 服务端模板注入
references/xxe.md                    — XML 外部实体
references/insecure_deserialization.md    — 不安全反序列化
references/arbitrary_file_upload.md      — 任意文件上传
references/privilege_escalation.md       — 越权提升
references/nosql_injection.md            — NoSQL 注入
references/graphql_injection.md          — GraphQL 注入
references/weak_crypto_hash.md           — 弱加密 / 弱哈希
references/information_disclosure.md     — 信息泄露
references/insecure_cookie.md            — 不安全的 Cookie 属性
references/open_redirect.md              — 开放重定向
references/trust_boundary.md             — 信任边界破坏
references/race_conditions.md            — 竞态条件 / TOCTOU
references/brute_force.md                — 暴力破解 / 撞库
references/default_credentials.md        — 默认 / 硬编码凭据
references/verification_code_abuse.md    — 验证码滥用
references/business_logic.md             — 业务逻辑缺陷
references/http_method_tamper.md         — HTTP 方法篡改
references/smuggling_desync.md           — HTTP 请求走私 / 失步
references/cve_patterns.md               — 已知 CVE 模式
references/supply_chain.md               — 供应链攻击（依赖投毒 / CI-CD 可变标签 / SBOM）
references/expression_language_injection.md — 表达式语言注入（SpEL / OGNL）
references/jndi_injection.md             — JNDI 注入（Log4Shell 类）
references/denial_of_service.md          — 拒绝服务 / 资源耗尽
references/php_security.md               — PHP 特定安全问题
references/mobile_security.md            — 移动端安全（Android / iOS）
references/session_fixation.md           — 会话固定
```

**加载策略：**
- 定向审查（如"检查 SQL 注入"）：只加载相关参考文档
- 完整审计：加载全部 35 份参考文档，系统化扫描
- 即使未被明确要求，也应加载 OWASP Top 风险对应的参考文档

---

### 第 3 步：分析代码 — Source→Sink 污点追踪

对每一类已加载的漏洞，执行污点分析：

1. **识别 Source（污点源）** — 用户可控输入的入口点：
   - HTTP 参数、请求头、Cookie、请求体
   - 文件上传
   - WebSocket 消息
   - 环境变量
   - 从数据库读取的用户数据、反序列化对象

2. **追踪数据流** — 沿以下路径跟踪数据：
   - 变量赋值、函数参数、返回值
   - 框架辅助函数、ORM 调用、模板渲染
   - 跨模块 / 跨服务边界

3. **检查 Sink（汇聚点）** — 接收污点数据的危险操作：
   - 查询执行（SQL、NoSQL、LDAP、XPath）
   - Shell / 操作系统命令执行
   - 文件系统操作
   - HTTP 客户端调用
   - 模板渲染 / eval / 表达式解析
   - 序列化 / 反序列化

4. **评估净化措施** — 在 Source 与 Sink 之间，检查是否存在：
   - 输入校验（白名单 vs 黑名单）
   - 上下文适配的编码 / 转义
   - 参数化（预处理语句）
   - 框架原生防护

5. **给出初步判定**：
   - **VULN（漏洞）**：污点到达 Sink 且无有效净化
   - **LIKELY VULN（疑似漏洞）**：存在净化但按参考文档启发式规则可被绕过
   - **SAFE（安全）**：存在有效净化或不存在污点路径

---

### 第 4 步：业务逻辑与认证授权分析

除污点追踪外，还需检查：
- 敏感端点缺少认证 / 授权
- 不安全的状态机迁移
- 并发操作中的竞态条件
- 组件之间不恰当的信任边界
- JWT 算法混淆、令牌固定、会话问题
- 默认 / 硬编码凭据
- 通过响应时间或响应差异进行的用户枚举

---

### 第 5 步：Judge — 有效性复核

上报之前，每条初步发现（VULN 或 LIKELY VULN）**必须通过 Judge 复核**。Judge 扮演对抗性第二意见，用于消除误报。

对每条候选发现，逐项回答以下问题：

#### 可达性检查
- [ ] Source 是否真的由用户控制，还是内部 / 受信任数据？
- [ ] 漏洞代码路径是否可从 HTTP 端点 / 入口点到达，还是死代码 / 仅内部使用？
- [ ] 是否存在上游防护（认证中间件、输入过滤器）在到达 Sink 之前阻断该路径？

#### 净化措施重新评估
- [ ] 是否存在第 3 步遗漏的净化？（检查父函数、中间件、框架内部）
- [ ] 该净化方法对该特定 Sink 与上下文是否充分？
- [ ] 框架是否为该模式提供了隐式防护？

#### 可利用性检查
- [ ] 污点值能否以触发漏洞的形式实际到达 Sink？
- [ ] 利用是否依赖特定环境、配置或权限级别？
- [ ] 对逻辑缺陷：业务影响是真实的还是假设性的？
- [ ] 所选标签是否为该发现最精确的有效标签？

#### Judge 判定

| 判定 | 含义 | 处理 |
|---------|---------|--------|
| **CONFIRMED（确认）** | 可达性 / 净化 / 可利用性检查全部通过 | 纳入报告 |
| **LIKELY（疑似）** | 大部分检查通过，仅剩一处不确定 | 纳入报告，标注不确定项 |
| **NEEDS CONTEXT（需上下文）** | 缺少运行时行为 / 配置 / 附加文件无法确定 | 标注为"缺少 X 无法验证" |
| **FALSE POSITIVE（误报）** | 找到防护的正面证据——引用净化、白名单检查、守卫或框架级自动防护的确切 文件+行号，证明 Sink 安全 | 静默丢弃 |

**仅 CONFIRMED 与 LIKELY 级别的发现会被上报。**

**误报举证责任**：任何一项检查结果为 `UNCERTAIN`（不确定）都不足以判定为 FALSE POSITIVE。若检查完 Sink、其调用方及框架内部后仍为 UNCERTAIN，应使用 `NEEDS CONTEXT`。只有找到并引用路径受到保护的正面证据时，才可使用 FALSE POSITIVE。

#### Judge 输出格式（内部使用，上报前）

```
Finding: VULN-NNN — <漏洞类别>
Reachability:   PASS / FAIL / UNCERTAIN — <原因>
Sanitization:   PASS / FAIL / UNCERTAIN — <原因>
Exploitability: PASS / FAIL / UNCERTAIN — <原因>
Judge Verdict:  CONFIRMED / LIKELY / NEEDS CONTEXT / FALSE POSITIVE
```

#### 误报防护护栏

**标签（Tags）**
- `default_credentials`：需存在接受该硬编码凭据的可达认证路径
- `weak_crypto_hash`：需直接使用弱加密/弱哈希——仅引入或使用第三方组件不算。涵盖弱算法（DES、RC4、ECB）与弱哈希（MD5、SHA-1 存密码）；不要单独使用 `weak_crypto` 标签
- `rce`：直接执行 shell/进程时优先使用 `command_injection`；不要用 `rce`/`command_injection` 替代 `spel_injection`
- 演示代码中的 `jndi_injection`：仅当 JNDI Sink 是主要利用路径时才报
- 宽泛标签（`trust_boundary`、`authentication`、`privilege_escalation`）：优先使用最窄的有效标签（`xff_spoofing`、`session_fixation`、`verification_code`）
- `open_redirect`：仅当攻击者可控的重定向是主要利用方式（非基础设施/解析器配置错误）
- `csrf`：对无状态、仅 Bearer Token 的 API（`SessionCreationPolicy.STATELESS`）跳过
- `insecure_deserialization`：若 `component_vulnerability` 已覆盖同一 Sink 则跳过
- `arbitrary_file_upload`：对有限制类型且存储于 Web 根目录之外的头像/资料上传跳过
- `session_fixation`：Spring Security 默认会话管理生效时跳过
- `information_disclosure`：对配置文件中的数据库凭据跳过——属部署问题而非应用层问题

**范围（Scope）**
- 演示/示例代码：唯一漏洞路径位于 `examples/`、`demo/`、`sample/`（或类似目录）时跳过；仅当缺陷位于库/SDK 自身时才上报
- 非默认配置：上报前先验证 DEFAULT 值。需要非默认/已弃用配置 → 上限为 `Low`；代码/文档明确标注 `legacy` 或弃用 → 上限为 `Informational`

**信任边界（Trust Boundary）**
- 操作者自伤：当"攻击者"输入来自操作者自己编写的配置文件（YAML/JSON/TOML）、操作者自行提供的 CLI 参数（`--file`、`--url`、`--chain-id`）或操作者必须显式运行的命令时，跳过
- 受信任的管理员角色：对 `onlyAdmin`/`onlyOwner`/`onlyPoolAdmin` 保护的操作跳过 `privilege_escalation`/`business_logic`（该角色按设计受信任）；仅当非特权用户也能到达同一路径时才上报
- 仅内部服务：整个代码库零认证且引用内部基础设施（VPC 变量、`EC2_INSTANCE_ID`、Eureka、Consul）时，跳过 `authentication` 与 `information_disclosure`——认证在网络层完成
- 代码生成器：对输入来自开发者控制的源码注释、注解或本地配置的代码生成工具（`protoc`、`swagger-codegen` 等）跳过 `injection`/`path_traversal`/`rce`

**协议与架构（Protocol & Architecture）**
- 协议设计性 SSRF：当按规范要求获取对等方提供的 URL 时（LNURL、UMA、OAuth discovery、WebFinger、OIDC discovery）跳过 `ssrf`；仅当实现允许协议不需要的 scheme（如 `file://`）或跳过了必需的域名校验时才上报
- 盲 SSRF：当以下三条全部成立时降级为 `Informational`：(a) 响应永远不会到达攻击者；(b) 对目标无有意义的副作用；(c) 无错误预言
- 有界 DoS：除非迭代/分配数据的上限由攻击者可控且无界，否则跳过 `denial_of_service`。天然有界的数据（区块链验证者集合、gas 限制、etcd/请求体大小上限）→ 不构成发现
- 暴力破解：仅当代码、框架配置或仓库引用的中间件中可见限流时才跳过 `brute_force`；不要假设基础设施层有限流
- 幂等重放：当操作幂等且参数经密码学签名（不可篡改）时，跳过重放/`business_logic`
- 库的死路径：代码库中没有真实调用方触发该漏洞参数组合，且该路径有告警日志 → `NEEDS CONTEXT`，不算发现

**平台（Platform）**
- Android 应用私有存储：生产 manifest 无 `android:allowBackup="true"` 时，对应用私有存储中的 `SharedPreferences`/`DataStore` 跳过 `insecure_storage`/`information_disclosure`
- Terraform state：属性标记 `Sensitive: true` 时，对向 state 写入密钥的 provider 跳过 `information_disclosure`
- 组织内 CI/CD：可变 action 标签（如 `@v3`）的 action 组织与仓库组织相同时跳过 `supply_chain`；仅上报第三方组织的 action
- 本地开发工具：README 描述为本地开发工具且无生产文档时跳过 `authentication`。例外：工具未绑定 `localhost`、在 API 响应中暴露 token 或允许破坏性操作时，上报（降级严重性）

---

#### 上报前检查清单

- [ ] 面向公网的服务，还是设计为仅内部（全站零认证 + 内部基础设施引用）？
- [ ] 生产代码，还是 demo/example/sample 目录？
- [ ] 攻击者确实不可信，而不是处于自身信任边界内的管理员/操作者？
- [ ] 验证 DEFAULT 配置值——攻击在默认配置下能否生效？
- [ ] SSRF 是否由协议规范要求？
- [ ] SSRF 响应是否可被攻击者获取（可读 / 副作用 / 错误预言）？
- [ ] 敏感存储是否受 OS 沙箱保护（Android 应用私有）？
- [ ] 重放：操作是否幂等且参数经签名绑定？
- [ ] 库：是否存在真实调用方触发漏洞路径？
- [ ] Terraform state 带 `Sensitive: true` —— 是否属设计使然？
- [ ] DoS：上限是否由攻击者控制且无界？
- [ ] CI/CD 可变标签：同组织还是第三方？
- [ ] 管理员操作是否位于其设计信任边界之内？

---

### 第 6 步：输出漏洞发现

#### 严重性分级

| 严重性 | 判定标准 |
|----------|----------|
| **Critical（严重）** | 直接 RCE、认证绕过、未认证数据暴露 |
| **High（高危）** | SQLi、SSRF、涉敏感数据的 IDOR、存储型 XSS、越权提升 |
| **Medium（中危）** | 反射型 XSS、CSRF、路径穿越、不安全反序列化 |
| **Low（低危）** | 信息泄露、开放重定向、弱加密、不安全 Cookie |
| **Info（提示）** | 缺少安全响应头、详细错误回显、纵深防御缺口 |

**严重性降级规则：** 当利用需要认证、特定非默认配置、链式前置条件，或仅能通过内部/管理员专属路径到达时，在类别默认级别基础下降一级；LIKELY 判定且可利用性标记为 UNCERTAIN 的发现，无论漏洞类型如何，一律封顶在类别默认级别之下的一级。

#### 发现格式

```
[SEVERITY] VULN-NNN — <漏洞类别>  [CONFIRMED | LIKELY]
File: <路径>:<行号>
Description: <一句话——漏洞是什么>
Impact: <攻击者能达成什么>
Evidence:
  <相关代码片段>
Judge: <一句话——为何通过复核>
Remediation: <具体修复方案——非泛泛建议>
Reference: references/<漏洞>.md
```

NEEDS CONTEXT 类发现的格式：

```
[UNVERIFIABLE] VULN-NNN — <漏洞类别>
File: <路径>:<行号>
Blocked by: <需要什么附加上下文>
```

#### 报告结构

报告输出采用**双轨制**，避免中间产物不一致：

- **对话内摘要**：在回复中直接给出 markdown 摘要（下方结构），供用户即时阅读；不落盘、不生成 `sast_report.md`
- **结构化落盘**：正式数据一律按第 7 步的 `<project>_report.json` schema 落盘，由报告生成器产出 docx/html——`sast_report.md` 不再作为中间产物

对话内摘要格式：

```markdown
# SAST 安全报告 — <目标>
Date: <日期>
Analyzer: 灵眸·天鉴（SpiritEye）v0.1.0

## 摘要
<2-3 句：按严重性统计发现总数、最严重问题>

## 严重发现（Critical）
## 高危发现（High）
## 中危发现（Medium）
## 低危发现（Low）
## 提示（Informational）
## 无法验证的发现（Unverifiable）

## 修复优先级
<有序修复清单>
```

---

### 第 7 步：生成并上传报告

每次审计都必须产出标准化报告并上传至 OSS。使用 `reports/` 中的报告生成器：

1. **整理结构化数据** — 将审计结果按 `reports/pikachu_report.json` 的 schema 组织为 `<project>_report.json`（报告元信息、目标、方法、含严重性统计/P0/P1 的摘要、章节、含描述/证据/利用/修复的发现列表、整改跟踪表）
2. **环境准备（首次使用）** — 安装报告生成器依赖：
   ```
   python -m pip install -r reports/requirements.txt
   ```
   依赖：`python-docx`（Word 报告，必装）、`oss2`（OSS 上传，仅 `--upload` 时需要）
3. **生成并上传** — 运行：
   ```
   python reports/generate_report.py reports/<project>_report.json --upload
   ```
   该命令在 JSON 所在目录生成 `<date>_<project>_安全自查报告.docx` 与 `.html`，并将两者上传至 OSS（目标地址由环境变量 `OSS_BUCKET` / `OSS_ENDPOINT` 指定，不在代码或文档中写死）。
   - OSS 凭证从环境变量 `OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET` 读取（切勿硬编码）
   - 跳过上传：去掉 `--upload`；重新生成 Word 占位符模板：加 `--make-template`
4. **回报结果** — 向用户提供本地文件路径与 OSS 公网 URL

---

## 核心原则

- **证据优先于断言**：始终展示漏洞代码路径，而非仅给出模式名称
- **上下文决定一切**：只有当 Sink 能收到用户可控数据时才成立
- **避免误报**：若存在净化，先验证其可绕过性再标记 VULN
- **精确表达**：包含确切文件路径与行号——绝不模糊
- **修复重于标记**：始终提供具体修复方案，而非只描述问题
- **语言感知**：将 Sink/Source 模式适配到具体语言与框架
