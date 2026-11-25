#!/usr/bin/env node
// 1.1.8 knowledge client sample.
// It accepts the live public origin or an explicit loopback port.
// It does not print the API key or the Ed25519 private key.

import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
export const PUBLIC_HOST = 'qianfan.43-164-130-42.sslip.io';
export const PUBLIC_BASE = `https://${PUBLIC_HOST}`;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);

export function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

export function canonicalKnowledgeEnrollment({ challengeId, challenge, nameDisplay, nameKey, publicKey }) {
  return `QF-ENROLL-KS-V1\nknowledge\n${challengeId}\n${challenge}\n${nameDisplay}\n${nameKey}\n${publicKey}\n`;
}

export function canonicalKnowledgeSignature({ keyId, method, requestTarget, timestamp, nonce, bodySha256Hex }) {
  return `QF-SIG-KS-V1\n${keyId}\n${method}\n${requestTarget}\n${timestamp}\n${nonce}\n${bodySha256Hex}\n`;
}

export function assertBaseAllowed(base) {
  let url;
  try {
    url = new URL(base);
  } catch {
    throw new Error('base 不是绝对 URL。停止。');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('base 协议不允许。停止。');
  }
  const loopback = LOOPBACK.has(url.hostname);
  const publicOrigin = url.hostname === PUBLIC_HOST && url.protocol === 'https:' && (url.port === '' || url.port === '443');
  if (!loopback && !publicOrigin) {
    throw new Error('示例只连接 https://qianfan.43-164-130-42.sslip.io 或带端口的本机回环。其他主机停止，不要改领用量池钥匙。');
  }
  if (loopback && !url.port) throw new Error('回环 URL 要带显式端口。停止。');
  return url;
}

export function generateIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = publicKey.export({ format: 'jwk' }).x;
  if (typeof publicKeyB64 !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(publicKeyB64)) {
    throw new Error('Ed25519 公钥不是 43 字符 base64url。停止。');
  }
  return { publicKey, privateKey, publicKeyB64 };
}

export function signBase64Url(privateKey, canonical) {
  const signature = sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('base64url');
  const raw = Buffer.from(signature, 'base64url');
  if (raw.length !== 64 || raw.toString('base64url') !== signature) {
    throw new Error('签名不是无填充的 64 字节 base64url。停止。');
  }
  return signature;
}

export function buildSignedHeaders({ privateKey, keyId, apiKey, method, target, body }) {
  const raw = Buffer.isBuffer(body) ? body : Buffer.from(body || '');
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = `n${randomBytes(18).toString('base64url')}`;
  const bodySha256Hex = sha256Hex(raw);
  const canonical = canonicalKnowledgeSignature({
    keyId,
    method,
    requestTarget: target,
    timestamp,
    nonce,
    bodySha256Hex,
  });
  return {
    headers: {
      authorization: `Bearer ${apiKey}`,
      'x-signature-key-id': keyId,
      'x-signature-timestamp': timestamp,
      'x-signature-nonce': nonce,
      'x-signature': signBase64Url(privateKey, canonical),
    },
    body: raw,
    canonical,
    bodySha256Hex,
  };
}

function stop(message) {
  const error = new Error(message);
  error.code = 'knowledge_stop';
  return error;
}

function transport(baseUrl) {
  return baseUrl.protocol === 'https:' ? https : http;
}

function requestPort(baseUrl) {
  if (baseUrl.port) return baseUrl.port;
  return baseUrl.protocol === 'https:' ? 443 : 80;
}

function rawRequest(baseUrl, method, target, headers, body) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body || '');
  return new Promise((resolve, reject) => {
    const req = transport(baseUrl).request({
      hostname: baseUrl.hostname,
      port: requestPort(baseUrl),
      method,
      path: target,
      headers,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        let json = null;
        if (raw.length > 0) {
          try { json = JSON.parse(raw.toString('utf8')); } catch { json = null; }
        }
        resolve({ status: res.statusCode, headers: res.headers, raw, json });
      });
    });
    req.setTimeout(10000, () => req.destroy(stop('知识请求超时。停止。')));
    req.on('error', reject);
    req.end(payload);
  });
}

function readStreamStart(baseUrl, target, headers) {
  return new Promise((resolve, reject) => {
    const req = transport(baseUrl).request({
      hostname: baseUrl.hostname,
      port: requestPort(baseUrl),
      method: 'GET',
      path: target,
      headers,
    }, (res) => {
      res.once('data', (chunk) => {
        const text = chunk.toString('utf8');
        res.destroy();
        req.destroy();
        resolve({ status: res.statusCode, headers: res.headers, chunk: text });
      });
    });
    req.setTimeout(5000, () => req.destroy(stop('MCP GET 超时。停止。')));
    req.on('error', reject);
    req.end();
  });
}

function rejectPurpose(response, what) {
  if (response.status === 404) throw stop(`${what} 不存在（404）。停止，不要改领用量池钥匙。`);
  if (response.status === 401 || response.status === 403) {
    const code = response.json?.error?.code || '';
    throw stop(`${what} 被拒绝 ${response.status} ${code}。停止，不要改用用量池钥匙。`);
  }
}

function writeKnowledgeSecret(home, value) {
  const dir = path.resolve(home);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'knowledge-secret.json');
  const tmp = path.join(dir, `.knowledge-secret.${process.pid}.tmp`);
  fs.writeFileSync(tmp, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
}

export async function runKnowledgeDemo({ base, name, expectPhrase, section, home }) {
  const baseUrl = assertBaseAllowed(base);
  const publicOrigin = baseUrl.hostname === PUBLIC_HOST;
  if (publicOrigin && typeof home !== 'string') {
    throw stop('公网知识钥匙只返回一次。传入 home 后示例才注册，并以 0600 保存，不打印钥匙。停止。');
  }
  const identity = generateIdentity();
  const challengeBody = Buffer.from(JSON.stringify({
    name,
    public_key: identity.publicKeyB64,
    storage_claim: 'software',
  }));
  const challenge = await rawRequest(baseUrl, 'POST', '/v1/knowledge/enrollment/challenges', {
    'content-type': 'application/json',
  }, challengeBody);
  rejectPurpose(challenge, '知识挑战');
  if (challenge.status !== 200 || !challenge.json) throw stop(`知识挑战失败 ${challenge.status}。停止。`);
  const canonical = canonicalKnowledgeEnrollment({
    challengeId: challenge.json.challenge_id,
    challenge: challenge.json.challenge,
    nameDisplay: challenge.json.name_display,
    nameKey: challenge.json.name_key,
    publicKey: challenge.json.public_key,
  });
  if (sha256Hex(Buffer.from(canonical, 'utf8')) !== challenge.json.canonical_sha256) {
    throw stop('canonical_sha256 与 QF-ENROLL-KS-V1 不一致。停止。');
  }
  if (challenge.json.purpose !== 'knowledge' || challenge.json.model_access !== false || challenge.json.billing !== 'none') {
    throw stop('挑战响应不是独立知识用途。停止。');
  }
  const registered = await rawRequest(baseUrl, 'POST', '/v1/knowledge/enrollment/register', {
    'content-type': 'application/json',
  }, Buffer.from(JSON.stringify({
    challenge_id: challenge.json.challenge_id,
    name,
    public_key: identity.publicKeyB64,
    signature: signBase64Url(identity.privateKey, canonical),
  })));
  rejectPurpose(registered, '知识注册');
  if (registered.status !== 201 || !registered.json) throw stop(`知识注册失败 ${registered.status}。停止。`);
  const apiKey = registered.json.api_key;
  const keyId = registered.json.key_id;
  if (typeof apiKey !== 'string' || !apiKey.startsWith('skk-') || typeof keyId !== 'string' || !keyId.startsWith('ksk_')) {
    throw stop('注册响应缺少知识钥匙前缀。停止。');
  }
  if (registered.json.purpose !== 'knowledge' || registered.json.model_access !== false || registered.json.api_key_delivery !== 'once' || registered.json.billing !== 'none') {
    throw stop('注册响应与知识钥匙合同不一致。停止。');
  }
  if (typeof home === 'string') {
    writeKnowledgeSecret(home, {
      purpose: 'knowledge',
      storage: 'software',
      private_key_jwk: identity.privateKey.export({ format: 'jwk' }),
      public_key: identity.publicKeyB64,
      api_key: apiKey,
      key_id: keyId,
    });
  }
  const sessionIdentity = { privateKey: identity.privateKey, apiKey, keyId };

  async function call(method, target, body, extra) {
    const signed = buildSignedHeaders({
      privateKey: sessionIdentity.privateKey,
      keyId,
      apiKey,
      method,
      target,
      body,
    });
    const response = await rawRequest(baseUrl, method, target, { ...signed.headers, ...extra }, signed.body);
    rejectPurpose(response, `${method} ${target.split('?')[0]}`);
    return response;
  }

  const listed = await call('GET', '/skills');
  if (listed.status !== 200) throw stop(`GET /skills 失败 ${listed.status}。停止。`);
  const revision = listed.json?.revision || null;
  const skillId = listed.json?.skills?.[0]?.skill_id || null;
  let searchMode = null;
  let readHasPhrase = null;
  if (expectPhrase) {
    if (!skillId || !revision) throw stop('本地库没有可检索的技能。停止。');
    const searchTarget = `/skills/search?q=${encodeURIComponent(expectPhrase)}&mode=lexical`;
    const searched = await call('GET', searchTarget);
    if (searched.status !== 200 || searched.json?.mode !== 'lexical' || !JSON.stringify(searched.json.results || []).includes(expectPhrase)) {
      throw stop('词法检索没有按 lexical 命中预期词。停止。');
    }
    searchMode = searched.json.mode;
    const readTarget = `/skills/${skillId}?revision=${revision}${section ? `&section=${encodeURIComponent(section)}` : ''}`;
    const read = await call('GET', readTarget);
    if (read.status !== 200 || typeof read.json?.text !== 'string' || !read.json.text.includes(expectPhrase)) {
      throw stop('按 revision 读取没有得到预期正文。停止。');
    }
    readHasPhrase = true;
  }

  const accept = 'application/json, text/event-stream';
  const protocol = '2025-03-26';
  const initBody = Buffer.from(JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: protocol, capabilities: {}, clientInfo: { name: 'pyccd-knowledge-example', version: '0' } },
  }));
  const init = await call('POST', '/mcp', initBody, { accept, 'content-type': 'application/json' });
  if (init.status !== 200 || init.json?.result?.serverInfo?.name !== 'qianfan-skill-readonly' || init.json?.result?.serverInfo?.version !== '1.1.8') {
    throw stop('MCP initialize 不是 1.1.8 只读技能服务。停止。');
  }
  const sessionHeader = init.headers['mcp-session-id'];
  const session = Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader;
  if (typeof session !== 'string' || session.length < 16) throw stop('initialize 没有返回 Mcp-Session-Id。停止。');
  const mcpHeaders = {
    accept,
    'content-type': 'application/json',
    'mcp-protocol-version': protocol,
    'mcp-session-id': session,
  };
  const initializedBody = Buffer.from(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
  const initialized = await call('POST', '/mcp', initializedBody, mcpHeaders);
  if (initialized.status !== 202) throw stop(`notifications/initialized 返回 ${initialized.status}。停止。`);
  const toolsBody = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }));
  const tools = await call('POST', '/mcp', toolsBody, mcpHeaders);
  const toolNames = tools.json?.result?.tools?.map((tool) => tool.name);
  if (tools.status !== 200 || toolNames?.join(',') !== 'skill_list,skill_search,skill_read') {
    throw stop('tools/list 不是三只读工具。停止。');
  }
  async function toolCall(id, toolName, args) {
    const body = Buffer.from(JSON.stringify({
      jsonrpc: '2.0',
      id,
      method: 'tools/call',
      params: { name: toolName, arguments: args },
    }));
    const response = await call('POST', '/mcp', body, mcpHeaders);
    if (response.status !== 200 || response.json?.result?.isError !== false) {
      throw stop(`${toolName} 失败。停止。`);
    }
    return JSON.parse(response.json.result.content[0].text);
  }
  const listedTool = await toolCall(3, 'skill_list', {});
  const searchArgs = { q: expectPhrase || 'example', mode: 'lexical' };
  const searchedTool = await toolCall(4, 'skill_search', searchArgs);
  if (searchedTool.mode !== 'lexical') throw stop('skill_search 不是 lexical。停止。');
  if (expectPhrase && !JSON.stringify(searchedTool.results || []).includes(expectPhrase)) {
    throw stop('skill_search 没有命中预期词。停止。');
  }
  let readOk = false;
  if (expectPhrase) {
    const readTool = await toolCall(5, 'skill_read', {
      skill_id: skillId,
      revision,
      ...(section ? { section } : {}),
    });
    if (readTool.revision !== revision || typeof readTool.text !== 'string' || !readTool.text.includes(expectPhrase)) {
      throw stop('skill_read 没有按 revision 读到预期正文。停止。');
    }
    readOk = true;
  } else if (skillId && revision) {
    await toolCall(5, 'skill_read', { skill_id: skillId, revision });
    readOk = true;
  }
  const streamHeaders = buildSignedHeaders({
    privateKey: sessionIdentity.privateKey,
    keyId,
    apiKey,
    method: 'GET',
    target: '/mcp',
    body: Buffer.alloc(0),
  }).headers;
  const stream = await readStreamStart(baseUrl, '/mcp', {
    ...streamHeaders,
    accept: 'text/event-stream',
    'mcp-protocol-version': protocol,
    'mcp-session-id': session,
  });
  if (stream.status === 401 || stream.status === 403 || stream.status === 404) {
    throw stop(`MCP GET 被拒绝 ${stream.status}。停止，不要改用用量池钥匙。`);
  }
  if (stream.status !== 200 || !String(stream.headers['content-type'] || '').includes('text/event-stream') || !stream.chunk.includes('stream')) {
    throw stop('MCP GET 不是 text/event-stream。停止。');
  }
  const deleted = await call('DELETE', '/mcp', Buffer.alloc(0), {
    'mcp-protocol-version': protocol,
    'mcp-session-id': session,
  });
  if (deleted.status !== 204) throw stop(`MCP DELETE 返回 ${deleted.status}。停止。`);

  return {
    base_host: baseUrl.hostname,
    deployment: publicOrigin ? 'public_1.1.8' : 'loopback',
    knowledge_release: '1.1.8',
    public_endpoint_used: publicOrigin,
    secret_persisted: typeof home === 'string',
    api_key_logged: false,
    api_key_prefix_ok: true,
    key_id_prefix_ok: true,
    challenge_status: challenge.status,
    register_status: registered.status,
    purpose: 'knowledge',
    model_access: false,
    http: {
      list_status: listed.status,
      revision,
      skill_id: skillId,
      search_mode: searchMode,
      read_has_phrase: readHasPhrase,
      listed_count: Array.isArray(listed.json?.skills) ? listed.json.skills.length : 0,
    },
    mcp: {
      initialize_status: init.status,
      server: init.json.result.serverInfo.name,
      server_version: init.json.result.serverInfo.version,
      instructions_mention_qf_sig_v1: String(init.json.result.instructions || '').includes('QF-SIG-V1'),
      signed_label: 'QF-SIG-KS-V1',
      initialized_status: initialized.status,
      tools: toolNames,
      skill_list_revision: listedTool.revision ?? null,
      skill_search_mode: searchedTool.mode,
      skill_read_ok: readOk,
      get_status: stream.status,
      get_event_stream: true,
      delete_status: deleted.status,
    },
  };
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key] = true;
    else {
      out[key] = next;
      i += 1;
    }
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.base || !args.name) {
    process.stderr.write('用法: node examples/knowledge-client.mjs --base <http://127.0.0.1:端口|https://qianfan.43-164-130-42.sslip.io> --name <显示名> [--home <目录> --expect <词> --section <章节id>]\n公网源站必须带 --home。钥匙和私钥不打印。端点不符时停止，不要改领用量池钥匙。\n');
    process.exit(2);
  }
  const report = await runKnowledgeDemo({
    base: args.base,
    name: args.name,
    expectPhrase: args.expect,
    section: args.section,
    home: typeof args.home === 'string' ? args.home : undefined,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message || '停止'}\n`);
    process.exit(1);
  });
}
