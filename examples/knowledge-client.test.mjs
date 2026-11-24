import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  EMPTY_BODY_SHA256,
  PLANNED_PUBLIC_HOST,
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

test('the sample refuses the planned public host before opening a socket', () => {
  assert.throws(() => assertBaseAllowed(`https://${PLANNED_PUBLIC_HOST}/mcp`), /尚未部署/);
  assert.throws(() => assertBaseAllowed('http://43.164.130.42:18080/mcp'), /尚未部署/);
  assert.throws(() => assertBaseAllowed('https://example.com'), /回环/);
  const allowed = assertBaseAllowed('http://127.0.0.1:18080');
  assert.equal(allowed.hostname, '127.0.0.1');
  assert.equal(allowed.port, '18080');
});

test('published docs keep the not-deployed stop rule and do not carry secrets', () => {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const guide = fs.readFileSync(path.join(root, 'docs/AGENT-ONBOARDING.md'), 'utf8');
  const example = fs.readFileSync(path.join(root, 'examples/knowledge-client.mjs'), 'utf8');
  for (const text of [readme, guide]) {
    assert.match(text, /尚未部署/);
    assert.match(text, /1\.1\.7/);
    assert.match(text, /https:\/\/qianfan\.43-164-130-42\.sslip\.io/);
    assert.equal(text.includes('独立端点已经可用'), false);
    assert.equal(text.includes('自动回退'), false);
    assert.equal(text.includes('自动改用用量池'), false);
  }
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
