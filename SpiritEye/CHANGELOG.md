# 变更日志（Changelog）

本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)（SemVer 2.0.0）。

## [0.1.0] - 2026-08-29

首个发布基线。

### 新增

- 供应链攻击知识库 `references/supply_chain.md`（依赖投毒、CI/CD 可变标签、SBOM、锁定文件漂移、未验证第三方 Action）
- 报告生成器依赖清单 `reports/requirements.txt` 及 SKILL.md 第 7 步环境准备说明
- 授权与合规边界声明：仅审计授权目标、只读分析、数据合规、禁止滥用
- 变更追踪机制（本文件）

### 修复

- 第 6/7 步中间产物不一致：明确"对话内 markdown 摘要 + JSON 结构化落盘"双轨，废弃 `sast_report.md` 作为正式中间产物

### 变更

- 漏洞知识库由 34 类扩展为 35 类（新增供应链攻击）

  
