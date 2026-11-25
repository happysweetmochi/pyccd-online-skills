import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  EMPTY_BODY_SHA256,
  PUBLIC_BASE,
  PUBLIC_HOST,
  assertBaseAllowed,
  buildSignedHeaders,
  canonicalKnowledgeEnrollment,
  canonicalKnowledgeSignature,
  generateIdentity,
  sha256Hex,
  signBase64Url,
} from './knowledge-client.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('knowledge canonical strings match the 1.1.8 byte layout', () => {
  const enrollment = canonicalKnowledgeEnrollment({
    challengeId: 'kch_test',
    challenge: 'chal',
    nameDisplay: '显示名',
    nameKey: '显示名',
    publicKey: 'A'.repeat(43),
  });
  assert.equal(
    enrollment,
    `QF-ENROLL-KS-V1\nknowledge\nkch_test\nchal\n显示名\n显示名\n${'A'.repeat(43)}\n`,
  );
  assert.equal(enrollment.split('\n')[1], 'knowledge');
  const signature = canonicalKnowledgeSignature({
    keyId: 'ksk_test',
    method: 'POST',
    requestTarget: '/mcp',
    timestamp: '1700000000',
    nonce: 'n0123456789abcdefXYZ_-',
    bodySha256Hex: EMPTY_BODY_SHA256,
  });
  assert.equal(
    signature,
    `QF-SIG-KS-V1\nksk_test\nPOST\n/mcp\n1700000000\nn0123456789abcdefXYZ_-\n${EMPTY_BODY_SHA256}\n`,
  );
  assert.notEqual(signature.split('\n')[0], 'QF-SIG-V1');
  assert.equal(sha256Hex(Buffer.alloc(0)), EMPTY_BODY_SHA256);
  assert.equal(createHash('sha256').update(Buffer.alloc(0)).digest('hex'), EMPTY_BODY_SHA256);
});

test('Ed25519 signature is 64 raw bytes and verifies the knowledge string', () => {
  const identity = generateIdentity();
  const canonical = canonicalKnowledgeSignature({
    keyId: 'ksk_test',
    method: 'GET',
    requestTarget: '/skills/search?q=zeta&mode=lexical',
    timestamp: '1700000000',
    nonce: 'n0123456789abcdefXYZ_-',
    bodySha256Hex: EMPTY_BODY_SHA256,
  });
  const signature = signBase64Url(identity.privateKey, canonical);
  const raw = Buffer.from(signature, 'base64url');
  assert.equal(raw.length, 64);
  assert.equal(raw.toString('base64url'), signature);
  assert.equal(signature.includes('='), false);
  const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: identity.publicKeyB64 }, format: 'jwk' });
  assert.equal(verify(null, Buffer.from(canonical, 'utf8'), publicKey, raw), true);
  const headers = buildSignedHeaders({
    privateKey: identity.privateKey,
    keyId: 'ksk_test',
    apiKey: 'skk-sample',
    method: 'GET',
    target: '/mcp',
    body: Buffer.alloc(0),
  });
  assert.equal(headers.bodySha256Hex, EMPTY_BODY_SHA256);
  assert.equal(headers.canonical.split('\n')[3], '/mcp');
  assert.match(headers.headers['x-signature-nonce'], /^[A-Za-z0-9_-]{16,128}$/);
  assert.match(headers.headers['x-signature-timestamp'], /^[1-9][0-9]{8,11}$/);
  assert.equal(headers.headers.authorization.startsWith('Bearer '), true);
  assert.equal(Object.hasOwn(headers.headers, 'authorization'), true);
});

test('the sample accepts the live origin and still rejects other hosts', () => {
  const live = assertBaseAllowed(`${PUBLIC_BASE}/mcp`);
  assert.equal(live.protocol, 'https:');
  assert.equal(live.hostname, PUBLIC_HOST);
  assert.equal(live.port, '');
  assert.throws(() => assertBaseAllowed(`http://${PUBLIC_HOST}/mcp`), /其他主机/);
  assert.throws(() => assertBaseAllowed('http://43.164.130.42:18080/mcp'), /其他主机/);
  assert.throws(() => assertBaseAllowed('https://example.com'), /其他主机/);
  const allowed = assertBaseAllowed('http://127.0.0.1:18080');
  assert.equal(allowed.hostname, '127.0.0.1');
  assert.equal(allowed.port, '18080');
});

test('published docs record the live release and do not carry secrets', () => {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const guide = fs.readFileSync(path.join(root, 'docs/AGENT-ONBOARDING.md'), 'utf8');
  const example = fs.readFileSync(path.join(root, 'examples/knowledge-client.mjs'), 'utf8');
  for (const text of [readme, guide, example]) {
    assert.equal(text.includes('尚未部署'), false);
    assert.equal(text.includes('当前是 1.1.7'), false);
    assert.equal(text.includes('当前是 **1.1.7**'), false);
    assert.equal(text.includes('不要向该公网主机发送'), false);
    assert.equal(text.includes('不要向上述公网主机发送'), false);
    assert.equal(text.includes('自动回退'), false);
    assert.equal(text.includes('自动改用用量池'), false);
  }
  for (const text of [readme, guide]) {
    assert.match(text, /2026-11-23 23:03:24 PST/);
    assert.match(text, /3f0a3588fdfaa26b8fbb5335443f5cea10fc59d3/);
    assert.match(text, /https:\/\/qianfan\.43-164-130-42\.sslip\.io/);
    assert.match(text, /wrong_key_purpose/);
    assert.match(text, /模板示例/);
    assert.match(text, /还没有同步/);
  }
  assert.match(guide, /public_base_status/);
  assert.match(guide, /online/);
  for (const needle of [
    'QF-ENROLL-KS-V1',
    'knowledge',
    'QF-SIG-KS-V1',
    EMPTY_BODY_SHA256,
    'wrong_key_purpose',
    'skill_list',
    'skill_search',
    'skill_read',
    'notifications/initialized',
    '2025-03-26',
    '2025-06-18',
    'skk-',
    'ksk_',
    'text/event-stream',
    'Mcp-Session-Id',
  ]) {
    assert.equal(guide.includes(needle), true, needle);
  }
  assert.match(example, /QF-ENROLL-KS-V1\\nknowledge\\n/);
  assert.match(example, /QF-SIG-KS-V1\\n/);
  const committed = [readme, guide, example, fs.readFileSync(path.join(root, 'examples/knowledge-client.test.mjs'), 'utf8')].join('\n');
  assert.equal(/skk-[A-Za-z0-9_-]{20,}/.test(committed), false);
  assert.equal(/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(committed), false);
  assert.equal(/"d"\s*:/.test(committed), false);
});
