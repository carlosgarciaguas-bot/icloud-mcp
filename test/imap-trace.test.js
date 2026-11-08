#!/usr/bin/env node
/**
 * Offline IMAP failure stages. The mock never leaves 127.0.0.1 and the
 * fixture identity must not appear in trace output or on the wire.
 */

process.env.ICLOUD_EMAIL = 'leak-check-user@example.com';
process.env.ICLOUD_APP_PASSWORD = 'leak-check-password-value';
process.env.USE_LOCAL_MODE = 'false';
delete process.env.ICLOUD_MCP_IMAP_TRACE;

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const config = require('../config');
const { emailTools } = require('../email');

const SECRET_USER = process.env.ICLOUD_EMAIL;
const SECRET_PASSWORD = process.env.ICLOUD_APP_PASSWORD;
const listFolders = emailTools.find((tool) => tool.name === 'list-folders').handler;

let pass = 0, fail = 0;
async function check(name, fn) {
  try { await fn(); console.log('  PASS  ' + name); pass++; }
  catch (e) { console.log('  FAIL  ' + name + ' -> ' + e.message); fail++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

function listen(onConnection) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    onConnection(socket);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        close() {
          for (const socket of sockets) socket.destroy();
          return new Promise((done) => server.close(() => done()));
        }
      });
    });
  });
}

function pointAt(port) {
  config.IMAP.HOST = '127.0.0.1';
  config.IMAP.PORT = port;
  config.IMAP.CONN_TIMEOUT = 2000;
  config.IMAP.AUTH_TIMEOUT = 2000;
}

async function callListFolders() {
  const lines = [];
  const original = console.error;
  console.error = (...args) => {
    lines.push(args.map((part) => String(part)).join(' '));
  };
  try {
    const result = await listFolders({});
    return { result, lines };
  } finally {
    console.error = original;
  }
}

function textOf(result) {
  return (result?.content || []).map((part) => part.text || '').join('\n');
}

function assertNoSecrets(blob, where) {
  assert(!blob.includes(SECRET_USER), where + ' contains the mailbox identity');
  assert(!blob.includes(SECRET_PASSWORD), where + ' contains the credential');
  assert(!blob.includes('leak-check'), where + ' contains the fixture marker');
}

(async () => {
  console.log('\nIMAP stage trace');

  await check('plain EOF before TLS stays the Node message when trace is off', async () => {
    const seen = [];
    const server = await listen((socket) => {
      socket.on('data', (chunk) => seen.push(chunk));
      socket.end();
    });
    pointAt(server.port);
    delete process.env.ICLOUD_MCP_IMAP_TRACE;
    const { result, lines } = await callListFolders();
    await server.close();
    const blob = textOf(result) + '\n' + lines.join('\n') + '\n' + Buffer.concat(seen).toString('utf8');
    assert(result.isError === true, 'expected an error result');
    assert(textOf(result).includes(
      'Client network socket disconnected before secure TLS connection was established'
    ), 'tool text: ' + textOf(result));
    assert(!blob.includes('imapTrace'), 'trace leaked while disabled');
    assertNoSecrets(blob, 'trace-off');
  });

  await check('opt-in trace records TLS EOF after TCP and omits secrets', async () => {
    const seen = [];
    const server = await listen((socket) => {
      socket.on('data', (chunk) => seen.push(chunk));
      socket.end();
    });
    pointAt(server.port);
    process.env.ICLOUD_MCP_IMAP_TRACE = '1';
    const { result, lines } = await callListFolders();
    await server.close();
    const wire = Buffer.concat(seen).toString('utf8');
    const blob = textOf(result) + '\n' + lines.join('\n') + '\n' + wire;
    assertNoSecrets(blob, 'trace-on eof');
    const traceLines = lines.filter((line) => line.includes('"imapTrace":true'));
    assert(traceLines.length >= 1, 'no trace line');
    const failure = JSON.parse(textOf(result).split('IMAP connection failed ')[1]);
    assert(failure.stage === 'tls-eof-before-secure', 'stage ' + failure.stage);
    assert(failure.tcpConnected === true, 'tcp was not observed');
    assert(failure.remoteFamily === 'IPv4', 'family ' + failure.remoteFamily);
    assert(failure.remotePort === server.port, 'port ' + failure.remotePort);
    assert(failure.auth === 'not-reached', 'auth ' + failure.auth);
    assert(failure.code === 'ECONNRESET', 'code ' + failure.code);
    assert(failure.source === 'socket', 'source ' + failure.source);
    assert(traceLines.some((line) => line.includes('"stage":"tcp-connect"')), 'missing tcp-connect');
    assert(!Object.prototype.hasOwnProperty.call(failure, 'user'), 'user field present');
    assert(!Object.prototype.hasOwnProperty.call(failure, 'password'), 'password field present');
  });

  await check('a self-signed certificate is a different stage and still leaks nothing', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'imap-trace-'));
    const keyPath = path.join(dir, 'key.pem');
    const certPath = path.join(dir, 'cert.pem');
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1',
      '-subj', '/CN=127.0.0.1'
    ], { stdio: 'ignore' });
    const seen = [];
    const sockets = new Set();
    const server = tls.createServer({
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    }, (socket) => {
      sockets.add(socket);
      socket.on('data', (chunk) => seen.push(chunk));
      socket.end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    pointAt(server.address().port);
    process.env.ICLOUD_MCP_IMAP_TRACE = '1';
    const { result, lines } = await callListFolders();
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    const blob = textOf(result) + '\n' + lines.join('\n') + '\n' + Buffer.concat(seen).toString('utf8');
    assertNoSecrets(blob, 'trace-on cert');
    const failure = JSON.parse(textOf(result).split('IMAP connection failed ')[1]);
    assert(failure.stage === 'tls-certificate', 'stage ' + failure.stage);
    assert(failure.code === 'DEPTH_ZERO_SELF_SIGNED_CERT', 'code ' + failure.code);
    assert(failure.auth === 'not-reached', 'auth ' + failure.auth);
    assert(failure.tcpConnected === true, 'tcp was not observed');
  });

  console.log('\n' + '='.repeat(56));
  console.log(fail === 0 ? 'ALL PASS (' + pass + ')' : 'PASS ' + pass + '  FAIL ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})();
