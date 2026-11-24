# 外部 Agent 接入指南

本文给外部 Agent 自己完成知识库接入。它核对的是网关源码包 **1.1.8** 的注册、签名和只读 MCP 合同。它不是部署记录。

## 部署状态：先停

**1.1.8 独立知识认证尚未部署。** 生产源站 `https://qianfan.43-164-130-42.sslip.io` 当前是 **1.1.7**。

在这份警告还在时：

- 不要向该公网主机发送 `POST /v1/knowledge/enrollment/challenges`、`POST /v1/knowledge/enrollment/register`、`GET /skills*` 或 `/mcp`。
- 不要把这些路径说成当前可用。
- 不要在 404、401、403 之后改领用量池钥匙，也不要回退到 `sk-` 或 `QF-SIG-V1`。
- 不要找运营人员手工要一把共用钥匙。知识钥匙由客户端自己向知识注册路径领取，而且不需要先领取用量池钥匙。
- `GET /healthz` 即使返回 200，也不证明知识路径存在。1.1.8 的 `/healthz` 不返回包版本号。未知路径返回 404 `not_found`。知识挑战返回 404 时，视为这版还没上线，停止。

部署公告改写本文之前，只允许把下文示例对到**本机回环**上的 1.1.8 进程。示例程序会拒绝计划中的公网主机。

## 接入时拿到什么

知识身份和用量池身份互不通用。

| | 知识库（本文） | 用量池（不要拿来读知识） |
| --- | --- | --- |
| 领取 | `POST /v1/knowledge/enrollment/challenges`，然后 `POST /v1/knowledge/enrollment/register` | 另一套路径，本文不使用 |
| 注册规范串 | `QF-ENROLL-KS-V1`，第二行固定 `knowledge` | `QF-ENROLL-V1` |
| 每次请求 | `QF-SIG-KS-V1` | `QF-SIG-V1` |
| 钥匙 | `skk-`，签名标识 `ksk_` | `sk-`，标识 `kid_` |
| 能读 | `GET /skills`、`GET /skills/search`、`GET /skills/{skill_id}`、远程 MCP `/mcp` | 模型与用量 |

交叉使用返回 **403** `wrong_key_purpose`：

- 用量池钥匙读知识 HTTP 或 `/mcp`：`用量池钥匙不能访问知识库。知识库要单独领取钥匙。`
- 知识钥匙访问模型、`/v1/models`、`/v1/usage`、`/v1/chat/completions`、`/v1/messages`：`知识库钥匙不能访问模型、用量或用量池管理。`

这种 403 不占用模型并发，也不表示可以换另一套钥匙再试。停止。

知识 HTTP 与 MCP 都是只读。没有提交技能正文的 HTTP 方法。内容变更只走 Git 协作。不需要本地 MCP 服务器，也不需要 stdio 代理。客户端自己对 HTTP 请求签名即可。

## 停止规则

遇到下面任一情况，结束这一次接入。不要自动重试成用量池注册，不要丢掉签名只填 URL 和钥匙，不要把密钥写进代码、Git 或日志。

1. **版本未上线。** 本文警告仍在，或知识挑战/注册/技能/MCP 返回 404 `not_found`。
2. **401。** 包括 `unauthorized`、`invalid_signature`、`key_mismatch`、`key_revoked`、`signature_stale`、`signature_replay`。不要重放同一个 nonce，不要改用 `sk-`。
3. **403 `wrong_key_purpose`。** 两套钥匙互相拒绝。停止，不要更换用途。
4. **403 `mcp_session_identity_mismatch` 或 `mcp_session_purpose_mismatch`。** 会话只属于创建它的那把知识钥匙。不要把会话交给另一把钥匙。
5. **`initialize` 的 `serverInfo.version` 不是 `1.1.8`。** 本文签名只对应这一版。不要沿用本文去猜别的规范串。

`initialize` 响应里的 `instructions` 在 1.1.8 源码中仍是这句话：

`只读技能检索。每次请求仍须 QF-SIG-V1。无写入、无执行。`

这句话过时。知识路径的验签标签是 **`QF-SIG-KS-V1`**。按 `QF-SIG-V1` 签名会 401。看到这句话也不要改签。

限速不是用途错误。429 `knowledge_enroll_limited` 或 `skill_rate_limited` 时，等窗口过去后仍用知识钥匙。不要换成用量池钥匙。410 `revision_expired` 时重新列出当前 revision，不要编造正文。406 表示 Accept 不符合下文，修正后用**新 nonce** 再签一次知识请求。

## 密钥放在哪里

客户端本地生成 Ed25519 密钥对。私钥只留在进程内存或调用方自己的 0600 文件里。本文示例不写文件、不打印私钥、不打印 `skk-` 钥匙。

- 公钥是 JWK 字段 `x`：32 字节原始公钥的 base64url，正好 43 个字符，字符集 `[A-Za-z0-9_-]`，没有 `=` 填充。解码后再编码必须与原字符串相同。
- 注册签名和请求签名都是 Ed25519（RFC 8032）对下文 UTF-8 规范串的签名。Node 的对应调用是 `sign(null, utf8Bytes, privateKey)`。结果是 64 字节，再用无填充 base64url。填充或长度不对会被拒绝。
- `api_key` 只出现在注册成功的那一次 201 响应里。服务端只保存该 UTF-8 字符串的 SHA-256 十六进制。丢失后不能再取回，只能用新的显示名重新注册。不要把它写入仓库、示例、测试输出或日志。

Node 22 内置 `node:crypto` 就够用，示例没有第三方依赖：

```javascript
import { generateKeyPairSync, sign } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyB64 = publicKey.export({ format: 'jwk' }).x;
const signature = sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('base64url');
```

## 独立注册

两条路径都不需要已有钥匙，也不产生模型用量。请求体最大 65536 字节，超过是 413 `payload_too_large`。同一来源地址默认 10 分钟最多 30 次知识领取请求，超过是 429 `knowledge_enroll_limited`。`Content-Type` 的媒体类型必须是 `application/json`。多余的 JSON 字段返回 400 `unsupported_parameter`。

### 1. 挑战

`POST /v1/knowledge/enrollment/challenges`

```json
{
  "name": "显示名",
  "public_key": "<43字符base64url公钥>",
  "storage_claim": "software"
}
```

`storage_claim` 可省略，默认 `software`。另一个允许值是 `hardware_unverified`，服务端不会把它当成已经验证的硬件证明。示例固定发送 `software`。

名字规则：最长 256 个 UTF-16 码元；拒绝 C0/C1 控制符、双向控制符和零宽字符；做 NFKC；收尾空白去掉，连续空白折成一个 U+0020；显示名保留大小写，长度为 1 到 64 个码位，且至少有一个字母或数字。查重键是该显示名的 `toLowerCase()`，并把 U+00DF 折成 `ss`。注册时要签的是响应里的 `name_display` 和 `name_key`，请求体里的 `name` 仍发送当初提交的同一字符串。

成功是 200，字段包括：

| 字段 | 含义 |
| --- | --- |
| `purpose` | `knowledge` |
| `challenge_id` | `kch_` 加 16 个随机字节的 base64url |
| `challenge` | 32 个随机字节的 base64url，无前缀 |
| `expires_at` | Unix 毫秒。默认现在加 600000，也就是 10 分钟 |
| `name_display` / `name_key` | 规范化后的显示名和查重键 |
| `public_key` | 原样回显 |
| `canonical_sha256` | 下面规范串 UTF-8 的 SHA-256，小写十六进制 |
| `storage_claim` | 接受的声明 |
| `billing` | `none` |
| `model_access` | `false` |
| `authenticity` | `unverified_public_enrollment` |
| `hardware_attestation` | `not_verified` |

`canonical_sha256` 与本地算出的摘要不一致时停止，不要签名。

名字已被占用是 409 `name_taken`。知识库和用量池的名字表是分开的，同名可以各自存在。不要为了占用检查去注册用量池。

### 2. 规范串 `QF-ENROLL-KS-V1`

七行 UTF-8，行尾都是 LF（U+000A），包括最后一行。没有空格，没有 CR。第二行是固定的小写单词 `knowledge`。

```javascript
function canonicalKnowledgeEnrollment({ challengeId, challenge, nameDisplay, nameKey, publicKey }) {
  return `QF-ENROLL-KS-V1\nknowledge\n${challengeId}\n${challenge}\n${nameDisplay}\n${nameKey}\n${publicKey}\n`;
}
```

展开后是：

```text
QF-ENROLL-KS-V1
knowledge
<challenge_id>
<challenge>
<name_display>
<name_key>
<public_key>
```

用私钥对这串字节签名，得到无填充 base64url。用量池的 `QF-ENROLL-V1` 没有 `knowledge` 这一行，拿去注册知识钥匙会 400 `challenge_invalid`。知识挑战也不能拿到用量池钥匙。用过的挑战不能再用。过期挑战同样是 400 `challenge_invalid`。

### 3. 注册

`POST /v1/knowledge/enrollment/register`

```json
{
  "challenge_id": "<上一步的 challenge_id>",
  "name": "显示名",
  "public_key": "<同一把公钥>",
  "signature": "<64字节签名的base64url>"
}
```

成功是 **201**。只此一次出现明文钥匙：

| 字段 | 含义 |
| --- | --- |
| `purpose` | `knowledge` |
| `key_id` | `ksk_` 加 16 个随机字节的 base64url |
| `api_key` | `skk-` 加 32 个随机字节的 base64url。只返回这一次 |
| `api_key_delivery` | `once` |
| `api_key_stored` | `sha256_only` |
| `billing` | `none` |
| `model_access` | `false` |
| `verified_person` | `false` |

响应里的声明写明：这是知识库身份，不是用量池钥匙，也不能调用模型。公开注册不证明真人、付费或正版程序。

## 之后每次请求的签名

规范串标签是 `QF-SIG-KS-V1`。同样是 UTF-8，七行，每行以 LF 结尾。

```javascript
function canonicalKnowledgeSignature({ keyId, method, requestTarget, timestamp, nonce, bodySha256Hex }) {
  return `QF-SIG-KS-V1\n${keyId}\n${method}\n${requestTarget}\n${timestamp}\n${nonce}\n${bodySha256Hex}\n`;
}
```

```text
QF-SIG-KS-V1
<key_id>
<大写方法>
<request_target>
<Unix秒>
<新nonce>
<原始body的小写SHA-256>
```

- `key_id` 是注册返回的 `ksk_...`，必须与 `X-Signature-Key-Id` 和这把钥匙一致。
- 方法是实际发出的大写方法，如 `GET`、`POST`、`DELETE`。
- `request_target` 是原始请求目标和查询串，不重排、不解码。`GET /skills/search?q=zeta&mode=lexical` 的目标就是 `/skills/search?q=zeta&mode=lexical`。查询字节必须和线上那一字节相同。
- MCP 的目标固定为 `/mcp`。加上查询串会 400 `bad_request`。
- 时间戳是 Unix 秒的十进制字符串，无前导零，匹配 `^[1-9][0-9]{8,11}$`。服务端用 `abs(现在毫秒 - 秒 * 1000) > 300000` 判定过期，也就是窗口 ±300 秒；差值大于 300000 毫秒才拒绝，代码是 `signature_stale`。
- nonce 每次新造，匹配 `^[A-Za-z0-9_-]{16,128}$`。示例使用 `n` 加 18 个随机字节的 base64url。同一把钥匙在 600000 毫秒内重复使用会 401 `signature_replay`。
- body 哈希是**发出去的原始字节**的 SHA-256，小写十六进制。空 body（GET、DELETE、以及没有正文的请求）固定是：

`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

签的是哪一段字节，线上就发哪一段。先签名再改 JSON，会 401 `invalid_signature`。

每个知识请求都带这些头：

```text
Authorization: Bearer <skk-钥匙>
X-Signature-Key-Id: <ksk_标识>
X-Signature-Timestamp: <Unix秒>
X-Signature-Nonce: <新nonce>
X-Signature: <64字节签名的base64url>
```

头名大小写不敏感。钥匙字符集是 `[A-Za-z0-9_-]`，长度 16 到 200。标识头最长 80，时间戳头最长 16，nonce 头最长 128，签名头最长 200。

错误体形状是：

```json
{ "error": { "message": "...", "type": "authentication_error", "code": "invalid_signature" } }
```

401 的 `type` 是 `authentication_error`。403 的 `type` 是 `permission_error`。

## 知识 HTTP

只接受 **GET**。其他方法在签名通过之后是 405 `method_not_allowed`。签名没通过则先返回 401 或 403。

这三条路径都不调用模型，也不是向量或语义检索。

| 方法 | 查询参数 |
| --- | --- |
| `GET /skills` | `domain`、`severity`、`limit`、`cursor`、`revision` |
| `GET /skills/search` | `q`、`domain`、`severity`、`limit`、`revision`、`cursor`、`mode` |
| `GET /skills/{skill_id}` | `file`、`section`、`max_chars`、`offset`、`revision` |

`skill_id`、`domain` 匹配 `^[a-z0-9][a-z0-9-]{0,63}$`。路径里不要写 `%`、`..` 或 `//`。`severity` 只允许 `info`、`warning`、`critical`。未知查询参数或重复参数是 400。

列表默认 20 条，最大 50。检索默认 8 条，最大 20。`q` 最长 200。`max_chars` 默认和上限都是 12000。`offset` 是非负整数。`revision` 是 40 位小写十六进制；不传表示当前快照。服务端保留最近 3 个 revision。不在保留集合里是 410 `revision_expired`。分页 `cursor` 原样放回查询串并签进 request target，不要自己拆开重排。游标绑定的 revision 过期是 410 `cursor_expired`。

同一把知识钥匙默认 10 秒内最多 30 次知识 HTTP 或 MCP 请求，超过是 429 `skill_rate_limited`。这和模型的 5 路并发不是一回事。

### 词法检索

`mode` 省略或 `lexical` 才接受。其他值，包括向量、语义、AI，返回 400 `search_mode_unsupported`，正文是：不支持该检索模式。当前只有普通词法检索 lexical。向量、语义和 AI 检索都未实现，不会改用词法结果冒充。

收到这个 400 就停止该次检索，不要把词法结果当成向量结果。

词法处理是：NFKC，再 `toLowerCase()`，然后按分隔符切开。分隔符是空格、制表、换行、`，。；、！？：`、`,;!?:`、中英文圆括号、引号、`【】` 和 `<>`。连字符不断开。最多 16 个词，所有词都要命中。每个结果最多 3 条片段，片段最长 160，上下文大约 48 个字符。

检索响应里的 `mode` 为 `lexical`。`results[]` 含 `skill_id`、`title`、`summary`、`score`、`files`、`sections` 和 `hits`。`hits[]` 含 `file`、`section`、`section_title`、`snippet`，用来定位下一次读取。

### 按 revision 读取

`GET /skills/{skill_id}?revision=<40位hex>` 读取该快照。省略 `file` 时读 `SKILL.md`。`file` 只允许 `SKILL.md` 或 `references/<名>.md`，`<名>` 匹配 `^[a-z0-9][a-z0-9-]{0,63}$`。

`section` 是标题 id，或唯一的 id 前缀。标题 id 来自 1 到 3 级 ATX 标题：小写，空白变 `-`，去掉不在 `[a-z0-9]`、中日韩统一表意文字和 `-` 里的字符，折叠重复的 `-`。空标题变成 `section`。重复标题依次加 `-2`、`-3`。前缀不唯一是 400 `ambiguous_section`，不存在是 400 `section_not_found`。

读取响应含 `revision`、`skill_id`、`file`、`section`、`offset`、`truncated`、`next_offset`、`text`。把列表或检索返回的 `revision` 原样传回去，读到的就是那一版。

列表响应含 `revision`、`domains`、`skills`、`next_cursor`。`skills[]` 只有元数据：`skill_id`、`domain`、`title`、`description`、`keywords`、`severity`、`updated`、`alert`、`files`。正文在读取接口里。

## 远程 MCP

传输是网关进程里的 Streamable HTTP，路径只有 `/mcp`。没有 stdio，也没有要在本地再起一个 MCP 服务器。

协议版本只接受 `2025-03-26` 和 `2025-06-18`。示例使用 `2025-03-26`。协商之后，后续请求都发送同一个 `MCP-Protocol-Version`。省略时服务端按 `2025-03-26` 理解；如果会话是 `2025-06-18`，省略会 400 `mcp_protocol_version`。

除 `initialize` 外，每个请求都带 `Mcp-Session-Id`。会话 id 长度 16 到 200。缺少或非法是 400 `mcp_session_required`。不存在是 404 `mcp_session_not_found`。空闲超过 30 分钟的会话会被丢掉。同时存在的会话超过 256 个时，新建会 429 `mcp_session_limit`。

**每一次** HTTP 调用都单独做 `QF-SIG-KS-V1`，包括下面的 initialize、initialized、tools/list、三次 tools/call、GET 和 DELETE。request target 都是 `/mcp`。POST 和 GET/DELETE 的 body 哈希按各自的原始字节计算；GET 和 DELETE 用空 body 哈希。

POST 的 `Accept` 必须同时含有 `application/json` 和 `text/event-stream`，否则 406 `not_acceptable`。GET 的 `Accept` 必须含有 `text/event-stream`，否则同样 406。

### 1. initialize

POST `/mcp`，不要带旧的会话头。

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-03-26",
    "capabilities": {},
    "clientInfo": { "name": "external-agent", "version": "0" }
  }
}
```

成功是 200，响应头 `Mcp-Session-Id` 是新会话。JSON-RPC 结果含：

- `protocolVersion`：请求的版本
- `capabilities.tools.listChanged`：`false`
- `serverInfo.name`：`qianfan-skill-readonly`
- `serverInfo.version`：`1.1.8`
- `instructions`：仍可能写着 `QF-SIG-V1`。忽略这句话，继续用 `QF-SIG-KS-V1`

不支持的 `protocolVersion` 是 HTTP 400，JSON-RPC `-32602`。

### 2. notifications/initialized

POST `/mcp`。这是通知，**没有** `id`。带上会话头和协议头，Accept 仍要两种类型。

```json
{ "jsonrpc": "2.0", "method": "notifications/initialized" }
```

成功是 **202**，空正文。如果加上 `id`，它会被当成普通请求，方法不存在。

### 3. tools/list

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }
```

成功是 200。`result.tools` 的名字顺序是 `skill_list`、`skill_search`、`skill_read`。没有第四个工具，也没有写入或执行工具。

### 4. 三次 tools/call

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": { "name": "skill_list", "arguments": {} }
}
```

把 `name` 换成三个工具。参数是对象，字段与 HTTP 查询对应：

| 工具 | 参数 |
| --- | --- |
| `skill_list` | `domain`、`severity`、`limit`（1–50）、`cursor`、`revision` |
| `skill_search` | `q` 必填，以及 `domain`、`severity`、`limit`（1–20）、`cursor`、`revision`、`mode` |
| `skill_read` | `skill_id` 必填，以及 `file`、`section`、`max_chars`（1–12000）、`offset`、`revision` |

`skill_search` 的 `mode` 只允许 `lexical` 或省略。成功时 HTTP 200，`result.isError` 为 `false`，正文在 `result.content[0].text`，内容是和对应 HTTP 接口相同的 JSON 字符串。工具参数错误时 HTTP 仍可能是 200，但 `isError` 为 `true`，文本里是 `{ "code", "message" }`。把 `isError: true` 当成这次调用失败，不要当成正文。

未知工具是 HTTP 200 加 JSON-RPC `-32602`。未知方法是 HTTP 200 加 `-32601`。JSON 解析失败是 HTTP 400 加 `-32700`。

一次完整读取是：`skill_list` 拿到 `revision` 和 `skill_id`，`skill_search` 用普通词法找到 `file` 和 `section`，`skill_read` 带上同一个 `revision` 读原文。

### 5. GET 会话

`GET /mcp`，无查询串，空 body，带会话头、协议头，以及 `Accept: text/event-stream`。成功是 200，`Content-Type` 含 `text/event-stream`，首段是：

```text
: stream

```

之后大约每 15 秒一行 `: ping`。这是保活注释，不是技能正文。确认首段后可以关闭连接。不要为了读技能去维持这条流。

### 6. DELETE 会话

`DELETE /mcp`，无查询串，空 body，带会话头和协议头。成功是 **204**。之后再用该会话是 404 `mcp_session_not_found`。

## 示例

可执行样本在仓库的 `examples/knowledge-client.mjs`。它实现了上面的规范串、注册、知识 HTTP、initialize、initialized、tools/list、三个工具、GET 和 DELETE。它只接受 `127.0.0.1`、`localhost` 或 `::1`，并且拒绝 `qianfan.43-164-130-42.sslip.io`。它不打印 `api_key` 或私钥。

```bash
node examples/knowledge-client.mjs --base http://127.0.0.1:<端口> --name <显示名>
```

本地库里有正文时，可以加上 `--expect <词> --section <章节id>`，样本会检查词法检索和按 revision 的读取。无参数的契约测试是：

```bash
node --test examples/knowledge-client.test.mjs
```

该测试不启动网关，也不访问公网。

把样本指到生产源站会直接停止。公网要等本文的部署警告被明确改掉之后，再用同一套签名重新实现；那之前不要去掉回环限制去试生产。
