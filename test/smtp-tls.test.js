#!/usr/bin/env node
/**
 * SMTP must fail closed without TLS.
 *
 * Talks to a local mock only. Credentials are fixtures, the socket never
 * leaves 127.0.0.1, and no message is accepted.
 */

process.env.ICLOUD_EMAIL = 'offline-mock@example.com';
process.env.ICLOUD_APP_PASSWORD = 'mock-not-a-credential';

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const config = require('../config');
const { sendEmail } = require('../email/smtp-client');

let pass = 0, fail = 0;

async function check(name, fn) {
  try { await fn(); console.log('  PASS  ' + name); pass++; }
  catch (e) { console.log('  FAIL  ' + name + ' -> ' + e.message); fail++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

function commandNames(lines) {
  return lines.map((line) => line.split(' ')[0].toUpperCase());
}

function listen(handler) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    handler(socket);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        port,
        close() {
          for (const socket of sockets) socket.destroy();
          return new Promise((done) => server.close(() => done()));
        }
      });
    });
  });
}

function readLines(socket, onLine) {
  let buffer = '';
  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let cut;
    while ((cut = buffer.indexOf('\r\n')) !== -1) {
      const line = buffer.slice(0, cut);
      buffer = buffer.slice(cut + 2);
      onLine(line);
    }
  });
}

function startPlain({ advertiseStartTls, onStartTls }) {
  const seen = [];
  return listen((socket) => {
    socket.write('220 localhost ESMTP\r\n');
    readLines(socket, (line) => {
      seen.push(line);
      const verb = line.split(' ')[0].toUpperCase();
      if (verb === 'EHLO' || verb === 'HELO') {
        const caps = advertiseStartTls
          ? '250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n'
          : '250-localhost\r\n250 AUTH PLAIN LOGIN\r\n';
        socket.write(caps);
      } else if (verb === 'STARTTLS') {
        if (onStartTls) onStartTls(socket);
        else socket.write('454 4.7.0 STARTTLS not available\r\n');
      } else if (verb === 'QUIT') {
        socket.write('221 bye\r\n');
        socket.end();
      } else {
        socket.write('503 5.5.1 not accepted\r\n');
      }
    });
  }).then((handle) => ({ ...handle, seen }));
}

async function expectFailClosed(handle) {
  config.SMTP.HOST = '127.0.0.1';
  config.SMTP.PORT = handle.port;
  let threw = false;
  let message = '';
  try {
    await sendEmail({ to: 'nobody@example.com', subject: 'offline', body: 'offline' });
  } catch (error) {
    threw = true;
    message = error.message || '';
  } finally {
    await handle.close();
  }
  assert(threw, 'sendEmail resolved without TLS');
  assert(message !== 'UNAUTHORIZED', 'TLS failure was reported as an auth failure');
  const verbs = commandNames(handle.seen);
  assert(verbs.includes('STARTTLS'), 'client did not ask for STARTTLS; saw ' + verbs.join(','));
  assert(!verbs.includes('AUTH'), 'client authenticated before TLS; saw ' + verbs.join(','));
  assert(!verbs.includes('MAIL'), 'client sent mail before TLS; saw ' + verbs.join(','));
  return message;
}

function selfSignedPair() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smtp-tls-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1',
    '-subj', '/CN=127.0.0.1'
  ], { stdio: 'ignore' });
  return {
    key: fs.readFileSync(key),
    cert: fs.readFileSync(cert)
  };
}

(async () => {
  console.log('\nSMTP fail-closed TLS');

  await check('missing STARTTLS is refused before AUTH', async () => {
    const handle = await startPlain({ advertiseStartTls: false });
    const message = await expectFailClosed(handle);
    assert(/STARTTLS|TLS/i.test(message), 'unexpected error: ' + message);
  });

  await check('refused STARTTLS is refused before AUTH', async () => {
    const handle = await startPlain({ advertiseStartTls: true });
    const message = await expectFailClosed(handle);
    assert(/STARTTLS|TLS/i.test(message), 'unexpected error: ' + message);
  });

  await check('a self-signed certificate is rejected before AUTH', async () => {
    const pair = selfSignedPair();
    const secureContext = tls.createSecureContext(pair);
    const tlsLines = [];
    const handle = await startPlain({
      advertiseStartTls: true,
      onStartTls(socket) {
        socket.removeAllListeners('data');
        socket.write('220 2.0.0 Ready to start TLS\r\n');
        const secure = new tls.TLSSocket(socket, { isServer: true, secureContext });
        readLines(secure, (line) => tlsLines.push(line));
        secure.on('error', () => {});
      }
    });
    const message = await expectFailClosed(handle);
    assert(/certificate|self.signed|unable to verify|altname|hostname/i.test(message), 'unexpected error: ' + message);
    assert(!commandNames(tlsLines).includes('AUTH'), 'client authenticated on an untrusted certificate');
  });

  console.log('\n' + '='.repeat(56));
  console.log(fail === 0 ? 'ALL PASS (' + pass + ')' : 'PASS ' + pass + '  FAIL ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})();
