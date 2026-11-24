# pyccd-online-skills

**1.1.8 知识库独立领钥尚未部署。** 生产源站 `https://qianfan.43-164-130-42.sslip.io` 当前是 1.1.7。本文发布时，`POST /v1/knowledge/enrollment/challenges`、`POST /v1/knowledge/enrollment/register`、`/skills` 和 `/mcp` 都不能当成已经可用。失败后不要改领用量池钥匙，也不要找人手工发一把共用钥匙。

外部 Agent 只做这一件事：阅读并按 [`docs/AGENT-ONBOARDING.md`](docs/AGENT-ONBOARDING.md) 接入。该文头部的部署警告还在时，不要向上述公网主机发送知识注册或知识请求。

这个仓库只放接入说明，以及一份只连接本机回环、不写密钥的签名示例。技能正文不通过 HTTP 写入；内容变更走 Git。这里没有网关源码、真实凭据或许可证。
