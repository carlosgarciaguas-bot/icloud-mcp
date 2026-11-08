/**
 * SMTP client wrapper for sending iCloud Mail
 */

const nodemailer = require('nodemailer');
const config = require('../config');
const { getCredentials } = require('../auth');

/**
 * Create SMTP transporter
 */
function createTransporter() {
  const creds = getCredentials();

  // Port 587 starts in clear and upgrades with STARTTLS. requireTLS makes a
  // missing or refused upgrade fail the connection before AUTH. Certificate
  // checks stay on even if NODE_TLS_REJECT_UNAUTHORIZED=0.
  return nodemailer.createTransport({
    host: config.SMTP.HOST,
    port: config.SMTP.PORT,
    secure: config.SMTP.SECURE,
    requireTLS: true,
    tls: { rejectUnauthorized: true },
    auth: {
      user: creds.email,
      pass: creds.password
    }
  });
}

/**
 * Send an email
 */
async function sendEmail({ to, cc, bcc, subject, body, isHtml = false }) {
  const creds = getCredentials();
  const transporter = createTransporter();

  const mailOptions = {
    from: creds.email,
    to,
    subject,
    [isHtml ? 'html' : 'text']: body
  };

  if (cc) mailOptions.cc = cc;
  if (bcc) mailOptions.bcc = bcc;

  try {
    const info = await transporter.sendMail(mailOptions);
    return {
      success: true,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected
    };
  } catch (error) {
    if (error.message?.includes('auth') || error.code === 'EAUTH') {
      throw new Error('UNAUTHORIZED');
    }
    throw error;
  }
}

/**
 * Verify SMTP connection
 */
async function verifyConnection() {
  const transporter = createTransporter();

  try {
    await transporter.verify();
    return true;
  } catch (error) {
    if (error.message?.includes('auth') || error.code === 'EAUTH') {
      throw new Error('UNAUTHORIZED');
    }
    throw error;
  }
}

module.exports = {
  sendEmail,
  verifyConnection
};
