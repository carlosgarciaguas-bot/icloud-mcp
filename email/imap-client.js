/**
 * IMAP client wrapper for iCloud Mail
 */

const net = require('net');
const Imap = require('imap');
const { simpleParser } = require('mailparser');
const config = require('../config');
const { getCredentials } = require('../auth');

// Node emits this exact text from tls.connect when the socket ends before
// the handshake is marked secure. It is not an authentication result.
const TLS_EOF_BEFORE_SECURE =
  'Client network socket disconnected before secure TLS connection was established';

const TLS_CERT_CODES = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_HAS_EXPIRED',
  'ERR_TLS_CERT_ALTNAME_INVALID'
]);

function imapTraceEnabled() {
  return process.env.ICLOUD_MCP_IMAP_TRACE === '1';
}

function safeToken(value, pattern) {
  return typeof value === 'string' && pattern.test(value) ? value : '';
}

function classifyImapFailure(err, tcp) {
  const message = typeof err?.message === 'string' ? err.message : '';
  const code = safeToken(err?.code, /^[A-Z0-9_]+$/);
  let stage = 'connection-failed';
  if (message === TLS_EOF_BEFORE_SECURE) stage = 'tls-eof-before-secure';
  else if (TLS_CERT_CODES.has(code)) stage = 'tls-certificate';
  else if (err?.source === 'timeout-auth') stage = 'auth-timeout';
  else if (err?.source === 'authentication' || message === 'UNAUTHORIZED') stage = 'auth-failed';
  else if (err?.source === 'timeout') stage = 'connect-timeout';
  else if (!tcp.connected) stage = 'before-tcp';
  else stage = 'after-tcp';

  let auth = 'not-reached';
  if (stage === 'auth-failed') auth = 'failed';
  else if (stage === 'auth-timeout') auth = 'waiting';

  const family = tcp.remoteFamily === 'IPv4' || tcp.remoteFamily === 'IPv6' ? tcp.remoteFamily : '';
  const remotePort = Number.isInteger(tcp.remotePort) ? tcp.remotePort : 0;

  return {
    stage,
    code,
    source: safeToken(err?.source, /^[a-z0-9-]+$/),
    syscall: safeToken(err?.syscall, /^[a-z0-9_]+$/),
    tcpConnected: tcp.connected === true,
    remoteFamily: family,
    remotePort,
    auth
  };
}

function emitImapTrace(info) {
  if (!imapTraceEnabled()) return;
  console.error(JSON.stringify({ imapTrace: true, ...info }));
}

/**
 * Create IMAP connection
 */
function createConnection(socket) {
  const creds = getCredentials();
  const options = {
    user: creds.email,
    password: creds.password,
    host: config.IMAP.HOST,
    port: config.IMAP.PORT,
    tls: config.IMAP.TLS,
    authTimeout: config.IMAP.AUTH_TIMEOUT,
    connTimeout: config.IMAP.CONN_TIMEOUT
  };
  if (socket) options.socket = socket;

  return new Imap(options);
}

/**
 * Execute IMAP operation with connection management
 */
function withImap(operation) {
  return new Promise((resolve, reject) => {
    const tcp = { connected: false, remoteFamily: '', remotePort: 0 };
    let socket;
    if (imapTraceEnabled()) {
      socket = new net.Socket();
      socket.once('connect', () => {
        tcp.connected = true;
        tcp.remoteFamily = socket.remoteFamily || '';
        tcp.remotePort = socket.remotePort || 0;
        emitImapTrace({
          stage: 'tcp-connect',
          code: '',
          source: '',
          syscall: '',
          tcpConnected: true,
          remoteFamily: tcp.remoteFamily === 'IPv4' || tcp.remoteFamily === 'IPv6' ? tcp.remoteFamily : '',
          remotePort: Number.isInteger(tcp.remotePort) ? tcp.remotePort : 0,
          auth: 'not-reached'
        });
      });
    }
    const imap = createConnection(socket);

    imap.once('ready', async () => {
      try {
        const result = await operation(imap);
        imap.end();
        resolve(result);
      } catch (err) {
        imap.end();
        reject(err);
      }
    });

    imap.once('error', (err) => {
      if (socket && (socket.remoteFamily === 'IPv4' || socket.remoteFamily === 'IPv6')) {
        tcp.connected = true;
        tcp.remoteFamily = socket.remoteFamily;
        tcp.remotePort = socket.remotePort || 0;
      }
      const authFailed = typeof err.message === 'string' && err.message.includes('AUTHENTICATIONFAILED');
      const reported = authFailed ? new Error('UNAUTHORIZED') : err;
      const info = classifyImapFailure(authFailed
        ? { message: 'UNAUTHORIZED', source: 'authentication', code: err.code }
        : err, tcp);
      emitImapTrace(info);
      if (imapTraceEnabled()) {
        reject(new Error('IMAP connection failed ' + JSON.stringify(info)));
      } else {
        reject(reported);
      }
    });

    imap.connect();
  });
}

/**
 * Get folder name from user-friendly name
 */
function getFolderName(folder) {
  const lower = (folder || 'inbox').toLowerCase();
  return config.EMAIL_FOLDERS[lower] || folder;
}

/**
 * List emails from a folder
 */
async function listEmails(folder = 'inbox', count = 25) {
  return withImap(async (imap) => {
    return new Promise((resolve, reject) => {
      const folderName = getFolderName(folder);

      imap.openBox(folderName, true, (err, box) => {
        if (err) {
          reject(err);
          return;
        }

        const total = box.messages.total;
        if (total === 0) {
          resolve([]);
          return;
        }

        // Fetch most recent emails
        const start = Math.max(1, total - count + 1);
        const range = `${start}:${total}`;

        const emails = [];
        const fetch = imap.seq.fetch(range, {
          bodies: ['HEADER.FIELDS (FROM TO SUBJECT DATE)'],
          struct: true
        });

        fetch.on('message', (msg, seqno) => {
          const email = { seqno, uid: null };

          msg.on('body', (stream, info) => {
            let buffer = '';
            stream.on('data', (chunk) => buffer += chunk.toString('utf8'));
            stream.on('end', () => {
              const headers = Imap.parseHeader(buffer);
              email.from = headers.from?.[0] || '';
              email.to = headers.to?.[0] || '';
              email.subject = headers.subject?.[0] || '(No subject)';
              email.date = headers.date?.[0] || '';
            });
          });

          msg.once('attributes', (attrs) => {
            email.uid = attrs.uid;
            email.flags = attrs.flags || [];
          });

          msg.once('end', () => {
            emails.push(email);
          });
        });

        fetch.once('error', reject);
        fetch.once('end', () => {
          // Sort by date descending (newest first)
          emails.sort((a, b) => new Date(b.date) - new Date(a.date));
          resolve(emails);
        });
      });
    });
  });
}

/**
 * Read full email content
 */
async function readEmail(uid, folder = 'inbox') {
  return withImap(async (imap) => {
    return new Promise((resolve, reject) => {
      const folderName = getFolderName(folder);

      imap.openBox(folderName, true, (err) => {
        if (err) {
          reject(err);
          return;
        }

        const fetch = imap.fetch(uid, { bodies: '' });
        let rawEmail = '';

        fetch.on('message', (msg) => {
          msg.on('body', (stream) => {
            stream.on('data', (chunk) => rawEmail += chunk.toString('utf8'));
          });
        });

        fetch.once('error', reject);
        fetch.once('end', async () => {
          try {
            const parsed = await simpleParser(rawEmail);
            resolve({
              uid,
              from: parsed.from?.text || '',
              to: parsed.to?.text || '',
              cc: parsed.cc?.text || '',
              subject: parsed.subject || '(No subject)',
              date: parsed.date,
              text: parsed.text || '',
              html: parsed.html || '',
              attachments: (parsed.attachments || []).map(a => ({
                filename: a.filename,
                contentType: a.contentType,
                size: a.size
              }))
            });
          } catch (parseErr) {
            reject(parseErr);
          }
        });
      });
    });
  });
}

/**
 * Search emails
 */
async function searchEmails(criteria, folder = 'inbox', count = 25) {
  return withImap(async (imap) => {
    return new Promise((resolve, reject) => {
      const folderName = getFolderName(folder);

      imap.openBox(folderName, true, (err, box) => {
        if (err) {
          reject(err);
          return;
        }

        // Build IMAP search criteria
        const searchCriteria = [];

        if (criteria.from) {
          searchCriteria.push(['FROM', criteria.from]);
        }
        if (criteria.subject) {
          searchCriteria.push(['SUBJECT', criteria.subject]);
        }
        if (criteria.since) {
          searchCriteria.push(['SINCE', criteria.since]);
        }
        if (criteria.before) {
          searchCriteria.push(['BEFORE', criteria.before]);
        }
        if (criteria.unseen) {
          searchCriteria.push('UNSEEN');
        }
        if (criteria.text) {
          searchCriteria.push(['TEXT', criteria.text]);
        }

        // Default to ALL if no criteria
        if (searchCriteria.length === 0) {
          searchCriteria.push('ALL');
        }

        imap.search(searchCriteria, (err, uids) => {
          if (err) {
            reject(err);
            return;
          }

          if (!uids || uids.length === 0) {
            resolve([]);
            return;
          }

          // Get most recent results
          const recentUids = uids.slice(-count);

          const emails = [];
          const fetch = imap.fetch(recentUids, {
            bodies: ['HEADER.FIELDS (FROM TO SUBJECT DATE)'],
            struct: true
          });

          fetch.on('message', (msg, seqno) => {
            const email = { seqno };

            msg.on('body', (stream) => {
              let buffer = '';
              stream.on('data', (chunk) => buffer += chunk.toString('utf8'));
              stream.on('end', () => {
                const headers = Imap.parseHeader(buffer);
                email.from = headers.from?.[0] || '';
                email.to = headers.to?.[0] || '';
                email.subject = headers.subject?.[0] || '(No subject)';
                email.date = headers.date?.[0] || '';
              });
            });

            msg.once('attributes', (attrs) => {
              email.uid = attrs.uid;
              email.flags = attrs.flags || [];
            });

            msg.once('end', () => {
              emails.push(email);
            });
          });

          fetch.once('error', reject);
          fetch.once('end', () => {
            emails.sort((a, b) => new Date(b.date) - new Date(a.date));
            resolve(emails);
          });
        });
      });
    });
  });
}

/**
 * Mark email as read/unread
 */
async function markAsRead(uid, folder = 'inbox', isRead = true) {
  return withImap(async (imap) => {
    return new Promise((resolve, reject) => {
      const folderName = getFolderName(folder);

      imap.openBox(folderName, false, (err) => {
        if (err) {
          reject(err);
          return;
        }

        const flags = ['\\Seen'];
        const method = isRead ? 'addFlags' : 'delFlags';

        imap[method](uid, flags, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve(true);
          }
        });
      });
    });
  });
}

/**
 * List folders
 */
async function listFolders() {
  return withImap(async (imap) => {
    return new Promise((resolve, reject) => {
      imap.getBoxes((err, boxes) => {
        if (err) {
          reject(err);
          return;
        }

        const folders = [];

        function processBoxes(boxObj, prefix = '') {
          for (const [name, box] of Object.entries(boxObj)) {
            const fullPath = prefix ? `${prefix}${box.delimiter}${name}` : name;
            folders.push({
              name: fullPath,
              delimiter: box.delimiter,
              flags: box.attribs || []
            });

            if (box.children) {
              processBoxes(box.children, fullPath);
            }
          }
        }

        processBoxes(boxes);
        resolve(folders);
      });
    });
  });
}

module.exports = {
  listEmails,
  readEmail,
  searchEmails,
  markAsRead,
  listFolders,
  getFolderName
};
