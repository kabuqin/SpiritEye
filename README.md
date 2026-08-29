# 灵眸·天鉴（SpiritEye）

AI 驱动的静态应用安全测试（SAST）工具，用于代码漏洞分析与安全审计。

## 名称寓意

- **灵眸**：AI 如鹰隼般敏锐的视觉，不放过任何代码异常
- **天鉴**：天的鉴察，呼应"审计"的严谨性

## 功能特性

- 覆盖 **35 类漏洞**知识库（SQL 注入、XSS、SSRF、RCE、越权、反序列化、XXE、供应链攻击等）
- **Source→Sink 污点追踪**：定位攻击者可控输入到危险函数的完整数据流
- **Judge 复核机制**：只报告 CONFIRMED/LIKELY 级别发现，显著降低误报
- 输出 **Word + HTML 双格式**安全自查报告，支持一键上传 OSS
- 支持 **Java、Python、JavaScript/TypeScript、PHP、.NET**

## 目录结构

```
SpiritEye/                    ← 灵眸·天鉴（SpiritEye）工具
├── README.md
├── SKILL.md                  # 技能主文件：7 步审计流程 + Judge 验证
├── references/               # 35 个漏洞知识库
├── reports/                  # 报告生成器与审计结果数据
│   ├── generate_report.py    # 报告生成 + OSS 上传
│   └── pikachu_report.json   # 审计结果样例（Pikachu 靶场，45 项发现）
└── pikachu-master/           # PHP 漏洞靶场（工具自测样例）
```

## 使用流程

1. **明确范围**：确定审计目标（文件/目录/模块/仓库）与语言
2. **加载知识库**：按目标语言与漏洞类型加载 `references/` 对应文档
3. **污点追踪**：Source（用户可控输入）→ 变换 → Sink（危险函数）
4. **业务逻辑分析**：越权、支付、验证码、会话等逻辑缺陷
5. **Judge 复核**：逐条验证，剔除误报
6. **整理数据**：审计结果填写为 `<项目>_report.json`
7. **生成上传**：生成报告并上传 OSS

## 报告生成

```bash
# 首次使用：安装报告生成器依赖（python-docx、oss2）
python -m pip install -r SpiritEye/reports/requirements.txt

# 生成 docx + html 报告
python reports/generate_report.py reports/<项目>_report.json

# 生成并上传 OSS
python reports/generate_report.py reports/<项目>_report.json --upload
```

OSS 配置全部通过环境变量提供（禁止写入代码/文档，防止仓库泄露）：
- 凭证：`OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET`
- 目标：`OSS_BUCKET`（bucket 名称）、`OSS_ENDPOINT`（如 `https://oss-cn-xxx.aliyuncs.com`，可选 `OSS_KEY_PREFIX` 自定义目录前缀，默认 `reports`）

## 使用方式（提示词示例）

向 AI 助手（如 Claude Code、Codex、Qoder 等）发送以下提示词，即可触发 SpiritEye 完整审计流程：

```text
使用 SpiritEye，对 pikachu-master 进行代码审计 + 渗透测试，并输出对应的 HTML 和 Word 报告，将报告上传至 OSS。
OSS 凭证：AK: <你的AccessKeyId>，SK: <你的AccessKeySecret>
```

其他常用提示词：

```text
使用 SpiritEye，对 <目标代码路径> 进行代码审计，输出漏洞清单与修复建议。
```

```text
使用 SpiritEye，审计 <目标代码路径> 的 SQL 注入与 XSS 漏洞，输出 HTML 报告。
```

> **说明**：
>
> - SpiritEye 会按 SKILL.md 流程执行：加载漏洞知识库 → Source→Sink 污点追踪 → 业务逻辑分析 → Judge 复核 → 整理 `<项目>_report.json` → 生成 docx/html 并上传 OSS
> - 提示词中的 AK/SK 为占位符，请替换为你的阿里云 AccessKey；真实密钥也可通过环境变量 `OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET` 提供
> - 切勿将真实 OSS 凭证写入仓库（`.gitignore` 已禁止凭证文件入库）

## 审计样例

`reports/pikachu_report.json` 为 Pikachu 漏洞靶场的完整审计结果（45 项发现，含渗透测试 payload 与修复建议），可作数据格式参考；对应报告见 `reports/` 目录下生成的 docx/html 文件。
