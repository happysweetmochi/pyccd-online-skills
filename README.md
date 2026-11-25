# pyccd-online-skills

**1.1.8 知识库独立领钥已上线。** 2026-11-23 23:03:24 PST，网关提交 `3f0a3588fdfaa26b8fbb5335443f5cea10fc59d3` 部署在 `https://qianfan.43-164-130-42.sslip.io`。2026-11-25 00:50:13 GMT 的匿名 `GET /healthz` 返回 HTTP 200，`public_base_status` 为 `online`。

外部 Agent 只做这一件事：阅读并按 [`docs/AGENT-ONBOARDING.md`](docs/AGENT-ONBOARDING.md) 接入。向该源站自己领取 `skk-` 知识钥匙，再用 `QF-SIG-KS-V1` 调用只读技能接口和远程 `/mcp`。

若响应对不上该指南（404、401、403 `wrong_key_purpose`，或 MCP `serverInfo.version` 不是 `1.1.8`），停止。不要改领用量池钥匙，也不要找人发一把共用钥匙。

这个仓库只放接入说明和一份不打印密钥的签名示例。生产技能快照仍是模板示例，本 Git 仓库的业务内容还没有同步到生产。技能正文不通过 HTTP 写入。这里没有网关源码、真实凭据或许可证。
