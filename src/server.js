'use strict';

const http = require('node:http');
const fsSync = require('node:fs');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const nodemailer = require('nodemailer');
const db = require('./db');

try {
  const dotenv = require('dotenv');
  dotenv.config();
  dotenv.config({ path: path.resolve(__dirname, '..', '.env') });
  dotenv.config({ path: path.resolve(__dirname, '.env') });
} catch {}

const envCandidates = [
  path.resolve(process.cwd(), '.env'),
  path.resolve(__dirname, '..', '.env'),
  path.resolve(__dirname, '.env'),
];

for (const envPath of envCandidates) {
  try {
    if (fsSync.existsSync(envPath)) {
      const envFile = fsSync.readFileSync(envPath, 'utf8');
      for (const line of envFile.split(/\r?\n/)) {
        const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
        if (match && process.env[match[1]] === undefined) {
          process.env[match[1]] = match[2].replace(/^(["'])(.*)\1$/, '$2');
        }
      }
    }
  } catch {}
}

const scrypt = promisify(crypto.scrypt);
const host = process.env.AUTH_HOST || '127.0.0.1';
const port = Number(process.env.AUTH_PORT || 4175);
const allowedOrigins = new Set(
  (process.env.DEEPORA_ALLOWED_ORIGINS || 'http://127.0.0.1:4173,http://localhost:4173')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean)
);
const sessionTtlMs = 7 * 24 * 60 * 60 * 1000;
const rateLimits = new Map();
const emailChallenges = new Map();
const verifiedEmailTokens = new Map();
let mongoRetryTimer = null;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webm': 'video/webm',
  '.mp4': 'video/mp4',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml',
  '.ico': 'image/x-icon',
};

function send(res, status, payload, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(payload));
}

function cors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const isLocalOrigin = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  const isVercelOrigin = /\.vercel\.app$/i.test(origin);
  const isAllowed = allowedOrigins.has('*') || allowedOrigins.has(origin) || isLocalOrigin || isVercelOrigin;
  if (!isAllowed) return false;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');
  return true;
}

async function readJson(req) {
  if (req.body !== undefined) {
    if (typeof req.body === 'object' && req.body !== null) return req.body;
    if (typeof req.body === 'string') {
      try {
        return JSON.parse(req.body);
      } catch {
        throw Object.assign(new Error('Please submit valid JSON data.'), { status: 400 });
      }
    }
  }

  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) throw Object.assign(new Error('Request is too large.'), { status: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('Please submit valid JSON data.'), { status: 400 });
  }
}

function rateLimit(key, max, intervalMs) {
  const now = Date.now();
  const current = rateLimits.get(key);
  if (!current || current.until <= now) {
    rateLimits.set(key, { count: 1, until: now + intervalMs });
    return true;
  }
  current.count += 1;
  return current.count <= max;
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : forwarded[0];
    if (first) return first.slice(0, 80);
  }
  const realIp = req.headers['x-real-ip'];
  if (realIp && typeof realIp === 'string') return realIp.slice(0, 80);
  return String(req.socket?.remoteAddress || 'unknown').slice(0, 80);
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function normalizePhone(value) {
  if (typeof value !== 'string') return '';
  const digits = value.replace(/\D/g, '');
  if (/^\d{10}$/.test(digits)) return `+91${digits}`;
  if (/^91\d{10}$/.test(digits)) return `+${digits}`;
  return value.trim().startsWith('+') ? `+${digits}` : digits;
}

function validPhone(value) {
  return /^\+91[6-9]\d{9}$/.test(value);
}

function validEmail(value) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function publicUser(user) {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    phone: user.phone || '',
    phoneVerified: Boolean(user.phoneVerified),
    email: user.email || '',
    state: user.state,
    city: user.city,
    addressFlat: user.addressFlat || '',
    addressBuilding: user.addressBuilding || '',
    addressStreet: user.addressStreet || '',
    pincode: user.pincode || '',
    addressLandmark: user.addressLandmark || '',
    googleMapsUrl: user.googleMapsUrl || '',
  };
}

function validMapsUrl(value) {
  if (!value) return true;
  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      (url.hostname === 'maps.google.com' ||
        url.hostname === 'www.google.com' ||
        url.hostname === 'google.com' ||
        url.hostname === 'maps.app.goo.gl')
    );
  } catch {
    return false;
  }
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function createEmailTransporter() {
  const user = process.env.SMTP_USER || process.env.ORDER_EMAIL_FROM || 'mayank.rana.mr12@gmail.com';
  const password = String(process.env.SMTP_APP_PASSWORD || process.env.ORDER_EMAIL_APP_PASSWORD || '').replace(/\s+/g, '');
  if (!password) {
    const error = new Error('Email is not configured. Set SMTP_APP_PASSWORD in the root .env file.');
    error.code = 'EMAIL_NOT_CONFIGURED';
    throw error;
  }

  const auth = { user, pass: password };
  const transportOptions = process.env.SMTP_HOST
    ? {
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 465),
        secure: String(process.env.SMTP_SECURE || 'true').toLowerCase() === 'true',
        auth,
      }
    : { service: 'gmail', auth };

  return nodemailer.createTransport({
    ...transportOptions,
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 25000,
  });
}

function emailFailureCode(error) {
  if (error?.code === 'EMAIL_NOT_CONFIGURED') return 'EMAIL_NOT_CONFIGURED';
  if (error?.code === 'EAUTH' || error?.responseCode === 535) return 'SMTP_AUTH_FAILED';
  if (['ETIMEDOUT', 'ECONNECTION', 'ESOCKET', 'EDNS'].includes(error?.code)) return 'SMTP_CONNECTION_FAILED';
  if (error?.responseCode >= 500) return 'SMTP_REJECTED';
  return 'EMAIL_DELIVERY_FAILED';
}

function emailChallengeSecret() {
  return String(process.env.AUTH_SECRET || process.env.SMTP_APP_PASSWORD || process.env.ORDER_EMAIL_APP_PASSWORD || 'deepora-email-verification').replace(/\s+/g, '');
}

async function sendOrderEmails(order, user) {
  const from = process.env.SMTP_USER || process.env.ORDER_EMAIL_FROM || 'mayank.rana.mr12@gmail.com';
  const to = process.env.ORDER_EMAIL_TO || 'mayank.rana.mr12@gmail.com';

  const address = order.deliveryAddress;
  const addressLines = [address.flat, address.building, address.street, address.landmark, address.city, address.state, address.pincode].filter(Boolean);
  if (address.googleMapsUrl) addressLines.push(`Google Maps: ${address.googleMapsUrl}`);
  const itemRowsText = order.items.map(item => `${item.quantity} x ${item.name} (${item.variant})${item.gift ? ' - GIFT' : ''}: ₹${item.lineTotal}`).join('\n');
  const itemRowsHtml = order.items.map(item => `<tr><td>${escapeHtml(item.quantity)} × ${escapeHtml(item.name)}<br><small>${escapeHtml(item.variant)}${item.gift ? ' · Gift from Deepora' : ''}</small></td><td style="text-align:right">₹${escapeHtml(item.lineTotal)}</td></tr>`).join('');
  const discountText = order.discount ? String(order.discount) : '0';
  const deliveryText = order.deliveryFee ? `₹${order.deliveryFee}` : 'Free';
  const billText = `Items subtotal: ₹${order.subtotal}\nReward discount: -₹${discountText}\nDelivery fee: ${deliveryText}\nConvenience fee: ₹${order.convenienceFee}\nGrand total: ₹${order.grandTotal}`;
  const customerText = `${user.firstName} ${user.lastName}\n${user.phone}\n${user.email || 'Email not provided'}\n${addressLines.join(', ')}`;
  const requestText = order.customerNote ? `\n\nCustomer request: ${order.customerNote}` : '';
  const commonHtml = `<h2>Deepora order ${escapeHtml(order.reference)}</h2><p>We will contact the customer on WhatsApp to confirm the order and share payment details.</p><table style="border-collapse:collapse;width:100%" cellpadding="8"><thead><tr><th align="left">Piece</th><th align="right">Amount</th></tr></thead><tbody>${itemRowsHtml}</tbody></table><hr><p>Items subtotal: ₹${order.subtotal}<br>Reward discount: -₹${discountText}<br>Delivery fee: ${deliveryText}<br>Convenience fee: ₹${order.convenienceFee}<br><strong>Grand total: ₹${order.grandTotal}</strong></p>`;
  const adminHtml = `${commonHtml}<hr><h3>Customer and delivery details</h3><p>${escapeHtml(user.firstName)} ${escapeHtml(user.lastName)}<br>Phone: ${escapeHtml(user.phone)}<br>Email: ${escapeHtml(user.email || 'Not provided')}<br>Delivery address: ${escapeHtml(addressLines.join(', '))}</p>${order.customerNote ? `<h3>Customer request</h3><p>${escapeHtml(order.customerNote)}</p>` : ''}`;
  const contactText = `Your order has been placed successfully. Our team will contact you on WhatsApp at ${user.phone} to confirm your order and share payment details. Please wait for our confirmation before making payment.`;
  const customerHtml = `${commonHtml}<p>${escapeHtml(contactText)}</p>${order.customerNote ? `<h3>Your request</h3><p>${escapeHtml(order.customerNote)}</p>` : ''}<h3>Delivering to</h3><p>${escapeHtml(customerText).replace(/\n/g, '<br>')}</p>`;
  let transporter;
  try {
    transporter = createEmailTransporter();
  } catch (error) {
    console.error('[Email] Order email configuration failed:', error.message);
    return { admin: false, customer: false, code: emailFailureCode(error) };
  }
  const [adminResult, customerResult] = await Promise.allSettled([
    transporter.sendMail({ from: `Deepora Orders <${from}>`, to, subject: `New Deepora order ${order.reference}`, text: `${commonHtml.replace(/<[^>]*>/g, ' ')}\n\nCUSTOMER\n${customerText}\n\n${itemRowsText}\n\n${billText}${requestText}`, html: adminHtml }),
    user.email ? transporter.sendMail({ from: `Deepora <${from}>`, to: user.email, subject: `Your Deepora order invoice ${order.reference}`, text: `${contactText}\n\nOrder reference: ${order.reference}\n\n${itemRowsText}\n\n${billText}${requestText}\n\nDelivering to:\n${customerText}`, html: customerHtml }) : Promise.reject(Object.assign(new Error('Customer email is missing'), { code: 'CUSTOMER_EMAIL_MISSING' })),
  ]);
  transporter.close();
  if (adminResult.status === 'rejected') console.error('[Email] Admin invoice delivery failed:', adminResult.reason?.message || 'Unknown error');
  if (customerResult.status === 'rejected') console.error('[Email] Customer invoice delivery failed:', customerResult.reason?.message || 'Unknown error');
  const firstFailure = [adminResult, customerResult].find(result => result.status === 'rejected');
  return {
    admin: adminResult.status === 'fulfilled',
    customer: customerResult.status === 'fulfilled',
    ...(firstFailure ? { code: firstFailure.reason?.code === 'CUSTOMER_EMAIL_MISSING' ? 'CUSTOMER_EMAIL_MISSING' : emailFailureCode(firstFailure.reason) } : {}),
  };
}

async function resendCustomerInvoice(order, user) {
  if (!user.email) {
    const error = new Error('Your account does not have an email address.');
    error.code = 'CUSTOMER_EMAIL_MISSING';
    throw error;
  }
  const from = process.env.SMTP_USER || process.env.ORDER_EMAIL_FROM || 'mayank.rana.mr12@gmail.com';
  const rows = order.items.map(item => `<tr><td>${escapeHtml(item.quantity)} × ${escapeHtml(item.name)}<br><small>${escapeHtml(item.variant)}${item.gift ? ' · Gift from Deepora' : ''}</small></td><td align="right">₹${escapeHtml(item.lineTotal)}</td></tr>`).join('');
  const textItems = order.items.map(item => `${item.quantity} x ${item.name} (${item.variant})${item.gift ? ' - GIFT' : ''}: ₹${item.lineTotal}`).join('\n');
  const address = order.deliveryAddress || {};
  const addressLines = [address.flat, address.building, address.street, address.landmark, address.city, address.state, address.pincode].filter(Boolean);
  if (address.googleMapsUrl) addressLines.push(`Google Maps: ${address.googleMapsUrl}`);
  const deliveryFee = order.deliveryFee ? `₹${order.deliveryFee}` : 'Free';
  const followup = `Your order has been placed successfully. Our team will contact you on WhatsApp at ${user.phone} to confirm your order and share payment details. Please wait for our confirmation before making payment.`;
  const requestText = order.customerNote ? `\n\nYour request: ${order.customerNote}` : '';
  const billText = `Items subtotal: ₹${order.subtotal}\nReward discount: -₹${order.discount || 0}\nDelivery fee: ${deliveryFee}\nConvenience fee: ₹${order.convenienceFee}\nGrand total: ₹${order.grandTotal}`;
  const html = `<h2>Your Deepora order invoice</h2><p>${escapeHtml(followup)}</p><p>Order reference: <strong>${escapeHtml(order.reference)}</strong></p><table style="border-collapse:collapse;width:100%" cellpadding="8"><thead><tr><th align="left">Piece</th><th align="right">Amount</th></tr></thead><tbody>${rows}</tbody></table><hr><p>Items subtotal: ₹${order.subtotal}<br>Reward discount: -₹${order.discount || 0}<br>Delivery fee: ${deliveryFee}<br>Convenience fee: ₹${order.convenienceFee}<br><strong>Grand total: ₹${order.grandTotal}</strong></p><h3>Delivering to</h3><p>${escapeHtml(`${user.firstName} ${user.lastName}\n${user.phone}\n${addressLines.join(', ')}`).replace(/\n/g, '<br>')}</p>`;
  const transporter = createEmailTransporter();
  try {
    await transporter.sendMail({ from: `Deepora <${from}>`, to: user.email, subject: `Your Deepora order invoice ${order.reference}`, text: `${followup}\n\nOrder reference: ${order.reference}\n\n${textItems}\n\n${billText}${requestText}\n\nDelivering to:\n${user.firstName} ${user.lastName}\n${user.phone}\n${addressLines.join(', ')}`, html: `${html}${order.customerNote ? `<h3>Your request</h3><p>${escapeHtml(order.customerNote)}</p>` : ''}` });
  } finally {
    transporter.close();
  }
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return { salt, hash: derived.toString('hex') };
}

function cookieValue(req, name) {
  const cookieHeader = req.headers.cookie || '';
  for (const piece of cookieHeader.split(';')) {
    const [key, ...value] = piece.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return '';
}

async function currentUser(req) {
  let token = cookieValue(req, 'deepora_session');
  if (!token && req.headers.authorization) {
    const match = req.headers.authorization.match(/^Bearer\s+(.+)$/i);
    if (match) token = match[1].trim();
  }
  if (!token) return null;
  const session = await db.findSession(token);
  return session ? db.findUserById(session.userId) : null;
}

async function issueSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + sessionTtlMs;

  await db.createSession(user.id, token, expiresAt);

  const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);
  const sameSite = process.env.COOKIE_SAMESITE || (isProd ? 'None' : 'Lax');
  const secure = (isProd || sameSite === 'None') ? '; Secure' : '';
  const cookie = `deepora_session=${encodeURIComponent(token)}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=${Math.floor(sessionTtlMs / 1000)}${secure}`;
  return { token, cookie };
}

function createStatelessVerificationToken(email) {
  const expiresAt = Date.now() + 15 * 60_000;
  const payload = `${email}:${expiresAt}`;
  const hmac = crypto.createHmac('sha256', emailChallengeSecret()).update(payload).digest('hex');
  return `${Buffer.from(payload).toString('base64url')}.${hmac}`;
}

function verifyStatelessVerificationToken(token, email) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [b64Payload, signature] = parts;
  let payload;
  try {
    payload = Buffer.from(b64Payload, 'base64url').toString('utf8');
  } catch {
    return false;
  }
  const [tokenEmail, expiresAtStr] = payload.split(':');
  const expiresAt = Number(expiresAtStr);
  if (!tokenEmail || !expiresAt || Date.now() > expiresAt) return false;
  if (tokenEmail.toLowerCase() !== email.toLowerCase()) return false;

  const expectedSig = crypto.createHmac('sha256', emailChallengeSecret()).update(payload).digest('hex');
  if (expectedSig.length !== signature.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSig, 'hex'));
  } catch {
    return false;
  }
}

async function getProductsCatalog() {
  return db.getAllProducts();
}

async function handle(req, res) {
  if (!cors(req, res)) {
    return send(res, 403, { error: 'This site is not allowed to use the Deepora service.' });
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || `${host}:${port}`;
  const protocol = req.headers['x-forwarded-proto'] || 'http';

  // On Vercel / serverless rewrites, req.url may be rewritten to '/api/index.js'.
  // Prefer x-matched-path, x-forwarded-uri, or x-original-url to get the actual client path.
  let targetPath = req.url || '/';
  if (req.headers['x-matched-path']) {
    targetPath = req.headers['x-matched-path'];
  } else if (req.headers['x-forwarded-uri']) {
    targetPath = req.headers['x-forwarded-uri'];
  } else if (req.headers['x-original-url']) {
    targetPath = req.headers['x-original-url'];
  } else if (targetPath.startsWith('/api/index.js') || targetPath.startsWith('/api/index')) {
    targetPath = '/';
  }

  // Preserve query string if x-matched-path stripped it
  if (req.url && req.url.includes('?') && !targetPath.includes('?')) {
    targetPath += req.url.slice(req.url.indexOf('?'));
  }

  if (req.url && (req.url.includes('debug=1') || req.headers['x-debug'] === '1')) {
    return send(res, 200, {
      reqUrl: req.url,
      targetPath,
      headers: req.headers,
    });
  }

  const url = new URL(targetPath, `${protocol}://${hostHeader}`);
  const ip = clientIp(req);

  // Lazy connect to MongoDB if not yet connected (essential for Vercel / serverless cold starts)
  if (!db.isConnected() && process.env.MONGODB_URI) {
    try {
      await db.connectToMongo();
    } catch (err) {
      console.error('[MongoDB] Connection error in request:', err.message);
    }
  }

  if (req.method === 'GET' && url.pathname === '/api/health/email') {
    let transporter;
    try {
      transporter = createEmailTransporter();
      await transporter.verify();
      transporter.close();
      return send(res, 200, { ok: true, configured: true, smtpConnected: true });
    } catch (error) {
      transporter?.close();
      const code = emailFailureCode(error);
      console.error('[Email] SMTP health check failed:', code, error.message);
      return send(res, 503, { ok: false, configured: code !== 'EMAIL_NOT_CONFIGURED', smtpConnected: false, code });
    }
  }

  // Email verification is independent of MongoDB so signup verification remains available during a database outage.
  if (req.method === 'POST' && url.pathname === '/api/auth/send-email-code') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }
    const email = normalizeEmail(body.email);
    if (!validEmail(email) || !/^[^\s@]+@gmail\.com$/i.test(email)) return send(res, 400, { error: 'Enter a valid Gmail address.' });
    if (!rateLimit(`email-code:${ip}`, 8, 60 * 60 * 1000)) return send(res, 429, { error: 'Too many verification requests. Try again later.' });
    const previous = emailChallenges.get(email);
    if (previous && previous.sentAt > Date.now() - 60_000) return send(res, 429, { error: 'Please wait one minute before requesting another code.' });
    const from = process.env.SMTP_USER || process.env.ORDER_EMAIL_FROM || 'mayank.rana.mr12@gmail.com';
    const code = String(crypto.randomInt(100000, 1000000));
    const codeHash = crypto.createHmac('sha256', emailChallengeSecret()).update(`${email}:${code}`).digest('hex');
    const challengeData = { codeHash, expiresAt: Date.now() + 10 * 60_000, sentAt: Date.now(), attempts: 0 };
    emailChallenges.set(email, challengeData);
    if (db.isConnected()) {
      await db.saveEmailChallenge(email, challengeData).catch(() => {});
    }
    let transporter;
    try {
      transporter = createEmailTransporter();
      await transporter.sendMail({ from: `Deepora <${from}>`, to: email, subject: 'Your Deepora verification code', text: `Your Deepora verification code is ${code}. It expires in 10 minutes. If you did not request this code, you can ignore this email.` });
      transporter.close();
      return send(res, 200, { ok: true, message: 'Verification code sent. Check your inbox.' });
    } catch (error) {
      transporter?.close();
      emailChallenges.delete(email);
      if (db.isConnected()) await db.deleteEmailChallenge(email).catch(() => {});
      const code = emailFailureCode(error);
      console.error('[Email] Verification code delivery failed:', code, error.message);
      const messages = {
        EMAIL_NOT_CONFIGURED: 'Email is not configured. Set SMTP_USER and SMTP_APP_PASSWORD in the root .env file, then restart npm start.',
        SMTP_AUTH_FAILED: 'Gmail rejected the SMTP login. Check SMTP_USER and the Gmail app password in the root .env file.',
        SMTP_CONNECTION_FAILED: 'The email server could not be reached. Check the network, SMTP host, and port.',
        SMTP_REJECTED: 'The email provider rejected the message. Check the sender account and recipient address.',
        EMAIL_DELIVERY_FAILED: 'The verification email could not be sent. Check the backend terminal for the email error.',
      };
      return send(res, 502, { error: messages[code], code });
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/verify-email-code') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }
    const email = normalizeEmail(body.email);
    const code = String(body.code || '').trim();
    let challenge = emailChallenges.get(email);
    if (!challenge && db.isConnected()) {
      challenge = await db.getEmailChallenge(email).catch(() => null);
    }
    if (!challenge || challenge.expiresAt < Date.now()) {
      emailChallenges.delete(email);
      if (db.isConnected()) await db.deleteEmailChallenge(email).catch(() => {});
      return send(res, 400, { error: 'That code has expired. Send a new verification code.' });
    }
    challenge.attempts += 1;
    if (db.isConnected()) {
      await db.incrementEmailChallengeAttempts(email).catch(() => {});
    }
    const submittedHash = crypto.createHmac('sha256', emailChallengeSecret()).update(`${email}:${code}`).digest('hex');
    const matches = /^\d{6}$/.test(code) && crypto.timingSafeEqual(Buffer.from(challenge.codeHash, 'hex'), Buffer.from(submittedHash, 'hex'));
    if (!matches) {
      if (challenge.attempts >= 5) {
        emailChallenges.delete(email);
        if (db.isConnected()) await db.deleteEmailChallenge(email).catch(() => {});
      }
      return send(res, 400, { error: challenge.attempts >= 5 ? 'Too many incorrect codes. Send a new code.' : 'That code is not correct. Please try again.' });
    }
    emailChallenges.delete(email);
    if (db.isConnected()) await db.deleteEmailChallenge(email).catch(() => {});
    const verificationToken = createStatelessVerificationToken(email);
    verifiedEmailTokens.set(verificationToken, { email, expiresAt: Date.now() + 15 * 60_000 });
    return send(res, 200, { ok: true, verificationToken });
  }

  // Health check
  if (req.method === 'GET' && url.pathname === '/api/health') {
    const isConn = db.isConnected();
    const lastErr = db.getLastMongoError();
    return send(res, isConn ? 200 : 503, {
      ok: isConn,
      database: 'mongodb',
      mongoConnected: isConn,
      configured: Boolean(process.env.MONGODB_URI),
      ...(isConn ? {} : { error: lastErr || 'MongoDB connection not established' }),
    });
  }

  if (url.pathname.startsWith('/api/') && !db.isConnected()) {
    return send(res, 503, { error: 'The database is temporarily unavailable. The service is retrying its MongoDB connection.' });
  }

  // Current authenticated user
  if (req.method === 'GET' && url.pathname === '/api/auth/me') {
    const user = await currentUser(req);
    return user ? send(res, 200, { user: publicUser(user) }) : send(res, 401, { error: 'Sign in to continue.' });
  }

  // Logout
  if (req.method === 'POST' && url.pathname === '/api/auth/logout') {
    let token = cookieValue(req, 'deepora_session');
    if (!token && req.headers.authorization) {
      const match = req.headers.authorization.match(/^Bearer\s+(.+)$/i);
      if (match) token = match[1].trim();
    }
    if (token) await db.deleteSession(token);
    const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);
    const sameSite = process.env.COOKIE_SAMESITE || (isProd ? 'None' : 'Lax');
    const secure = (isProd || sameSite === 'None') ? '; Secure' : '';
    return send(res, 200, { ok: true }, { 'Set-Cookie': `deepora_session=; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=0${secure}` });
  }

  // ======================== PRODUCT CATALOG APIs ========================
  // GET /api/products
  if (req.method === 'GET' && url.pathname === '/api/products') {
    const catalog = await getProductsCatalog();
    return send(res, 200, catalog);
  }

  // GET /api/products/:id
  if (req.method === 'GET' && url.pathname.startsWith('/api/products/')) {
    const productId = decodeURIComponent(url.pathname.slice('/api/products/'.length));
    const product = await db.getProductById(productId);
    if (!product) return send(res, 404, { error: 'Product not found.' });
    return send(res, 200, product);
  }

  // POST /api/products (Create/Upsert product in MongoDB)
  if (req.method === 'POST' && url.pathname === '/api/products') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }

    if (!body || typeof body.id !== 'string' || !body.id.trim() || typeof body.name !== 'string' || !body.name.trim()) {
      return send(res, 400, { error: 'Product must include a valid string "id" and "name".' });
    }
    if (typeof body.price !== 'number' || body.price < 0) {
      return send(res, 400, { error: 'Product price must be a positive number.' });
    }

    const productDoc = {
      id: body.id.trim(),
      name: body.name.trim(),
      category: body.category || 'diya',
      description: body.description || '',
      price: body.price,
      stock: Number.isInteger(body.stock) ? body.stock : 0,
      material: body.material || '',
      subtitle: body.subtitle || '',
      label: body.label || '',
      image: body.image || 'assets/og-diya.jpg',
      gift: Boolean(body.gift),
      variants: Array.isArray(body.variants) && body.variants.length > 0 ? body.variants : [
        { id: 'single', label: '1 Diya', price: body.price, units: 1 }
      ],
    };

    const saved = await db.upsertProduct(productDoc);
    return send(res, 201, { ok: true, product: saved });
  }

  // PUT /api/products/:id (Update product in MongoDB)
  if ((req.method === 'PUT' || req.method === 'PATCH') && url.pathname.startsWith('/api/products/')) {
    const productId = decodeURIComponent(url.pathname.slice('/api/products/'.length));
    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }

    const existing = await db.getProductById(productId);
    if (!existing) return send(res, 404, { error: `Product "${productId}" not found in database.` });
    const updated = await db.updateProduct(productId, body);
    return send(res, 200, { ok: true, product: updated });
  }

  // DELETE /api/products/:id
  if (req.method === 'DELETE' && url.pathname.startsWith('/api/products/')) {
    const productId = decodeURIComponent(url.pathname.slice('/api/products/'.length));
    const deleted = await db.deleteProduct(productId);
    if (!deleted) return send(res, 404, { error: `Product "${productId}" not found.` });
    return send(res, 200, { ok: true, deleted: productId });
  }

  // ======================== ORDERS ========================
  // GET /api/cart and PUT /api/cart keep each signed-in customer's bag separate.
  if (url.pathname === '/api/cart' && (req.method === 'GET' || req.method === 'PUT')) {
    const user = await currentUser(req);
    if (!user) return send(res, 401, { error: 'Sign in to access your bag.' });
    if (req.method === 'GET') return send(res, 200, { items: Array.isArray(user.cart) ? user.cart : [] });

    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }
    if (!Array.isArray(body.items) || body.items.length > 30) return send(res, 400, { error: 'Your bag has too many different items.' });
    const items = [];
    for (const line of body.items) {
      if (!line || typeof line.id !== 'string' || line.id.length > 120 || typeof line.variant !== 'string' || line.variant.length > 80 || !Number.isInteger(line.quantity) || line.quantity < 1 || line.quantity > 50) {
        return send(res, 400, { error: 'A bag item is invalid.' });
      }
      items.push({ id: line.id, variant: line.variant, quantity: line.quantity });
    }
    const savedUser = await db.updateUser(user.id, { cart: items });
    if (!savedUser) return send(res, 500, { error: 'Your bag could not be saved.' });
    return send(res, 200, { items });
  }

  const resendInvoiceMatch = url.pathname.match(/^\/api\/orders\/([^/]+)\/resend-invoice$/);
  if (req.method === 'POST' && resendInvoiceMatch) {
    const user = await currentUser(req);
    if (!user) return send(res, 401, { error: 'Sign in to resend your invoice.' });
    const reference = decodeURIComponent(resendInvoiceMatch[1]);
    const order = await db.findOrderByReference(reference);
    if (!order || order.userId !== user.id) return send(res, 404, { error: 'That order could not be found.' });
    try {
      await resendCustomerInvoice(order, user);
      return send(res, 200, { ok: true, email: user.email });
    } catch (error) {
      const code = error.code === 'CUSTOMER_EMAIL_MISSING' ? error.code : emailFailureCode(error);
      console.error('[Email] Customer invoice resend failed:', code, error.message);
      return send(res, 502, { error: code === 'CUSTOMER_EMAIL_MISSING' ? 'Add an email address to your account before resending the invoice.' : 'The invoice could not be sent. Check the backend email status and try again.', code });
    }
  }

  const orderReferenceMatch = url.pathname.match(/^\/api\/orders\/([^/]+)$/);
  if (req.method === 'GET' && orderReferenceMatch) {
    const user = await currentUser(req);
    if (!user) return send(res, 401, { error: 'Sign in to view this order.' });
    const order = await db.findOrderByReference(decodeURIComponent(orderReferenceMatch[1]));
    if (!order || order.userId !== user.id) return send(res, 404, { error: 'That order could not be found.' });
    return send(res, 200, { order, customer: { firstName: user.firstName, email: user.email || '' } });
  }

  if (req.method === 'POST' && url.pathname === '/api/feedback') {
    const user = await currentUser(req);
    if (!user) return send(res, 401, { error: 'Sign in to send feedback.' });
    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }
    const orderReference = String(body.orderReference || '').trim().slice(0, 40);
    const rating = Number(body.rating);
    const comment = String(body.comment || '').trim().slice(0, 1200);
    if (!/^DP-[A-F0-9]{8}$/i.test(orderReference)) return send(res, 400, { error: 'A valid order reference is required.' });
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) return send(res, 400, { error: 'Choose a rating from 1 to 5.' });
    if (!comment) return send(res, 400, { error: 'Please write a short note about your experience.' });
    const order = await db.findOrderByReference(orderReference);
    if (!order || order.userId !== user.id) return send(res, 404, { error: 'That order could not be found.' });
    await db.saveFeedback({ orderReference, userId: user.id, name: `${user.firstName} ${user.lastName}`.trim(), email: user.email || '', rating, comment });
    return send(res, 201, { ok: true, message: 'Thank you. Your feedback has been saved.' });
  }

  // GET /api/orders (Fetch user orders)
  if (req.method === 'GET' && url.pathname === '/api/orders') {
    const user = await currentUser(req);
    if (!user) return send(res, 401, { error: 'Sign in to view your orders.' });

    const userOrders = await db.findOrdersByUserId(user.id);
    return send(res, 200, { orders: userOrders });
  }

  // POST /api/orders (Place order and save into MongoDB)
  if (req.method === 'POST' && url.pathname === '/api/orders') {
    const user = await currentUser(req);
    if (!user) return send(res, 401, { error: 'Sign in before placing your order.' });
    if (!user.addressFlat || !user.addressBuilding || !user.addressStreet || !/^\d{6}$/.test(user.pincode || '')) {
      return send(res, 400, { error: 'Your account needs a complete delivery address before placing an order.' });
    }

    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }

    if (!Array.isArray(body.items) || body.items.length < 1 || body.items.length > 30) {
      return send(res, 400, { error: 'Your bag is empty or has too many different items.' });
    }
    const customerNote = String(body.customerNote || '').trim().slice(0, 1200);

    const catalog = await getProductsCatalog();
    if (!catalog.length) {
      return send(res, 503, { error: 'The product catalog is temporarily unavailable.' });
    }

    const items = [];
    let subtotal = 0;
    for (const requested of body.items) {
      const product = catalog.find(item => item.id === requested?.id);
      const variant = product?.variants?.find(item => item.id === requested?.variant) || product?.variants?.[0];
      if (
        !product ||
        !variant ||
        !Number.isInteger(requested.quantity) ||
        requested.quantity < 1 ||
        requested.quantity > Math.min(product.stock, 50)
      ) {
        return send(res, 400, {
          error: 'One of the items in your bag is no longer available. Refresh the collection and try again.',
        });
      }
      const lineTotal = variant.price * requested.quantity;
      subtotal += lineTotal;
      items.push({
        productId: product.id,
        name: product.name,
        variant: variant.label,
        quantity: requested.quantity,
        unitPrice: variant.price,
        lineTotal,
        gift: false,
      });
    }

    const gifts = [];
    if (subtotal >= 200) gifts.push(catalog.find(item => item.id === 'og-diya'));
    if (subtotal >= 350) gifts.push(catalog.find(item => item.id === 'drip-diya'));
    for (const product of gifts.filter(Boolean)) {
      items.push({
        productId: product.id,
        name: product.name,
        variant: 'Gift from Deepora',
        quantity: 1,
        unitPrice: 0,
        lineTotal: 0,
        gift: true,
      });
    }

    const discount = subtotal >= 500 ? 50 : 0;
    const deliveryFee = subtotal < 100 ? 89 : 0;
    const convenienceFee = 9;
    const order = {
      reference: `DP-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
      userId: user.id,
      items,
      subtotal,
      discount,
      deliveryFee,
      convenienceFee,
      grandTotal: subtotal - discount + deliveryFee + convenienceFee,
      deliveryAddress: {
        flat: user.addressFlat,
        building: user.addressBuilding,
        street: user.addressStreet,
        landmark: user.addressLandmark || '',
        city: user.city,
        state: user.state,
        pincode: user.pincode,
        googleMapsUrl: user.googleMapsUrl || '',
      },
      status: 'placed',
      paymentStatus: 'not-configured',
      customerNote,
      createdAt: new Date().toISOString(),
    };

    await db.createOrder(order);
    const emailDelivery = await sendOrderEmails(order, user);

    return send(res, 201, {
      order: {
        reference: order.reference,
        subtotal,
        discount,
        deliveryFee,
        convenienceFee,
        grandTotal: order.grandTotal,
        items,
      },
      emailDelivery,
    });
  }

  // ======================== AUTHENTICATION ========================
  // POST /api/auth/signup
  if (req.method === 'POST' && url.pathname === '/api/auth/signup') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }

    const firstName = String(body.firstName || '').trim().slice(0, 80);
    const lastName = String(body.lastName || '').trim().slice(0, 80);
    const phone = normalizePhone(body.phone);
    const email = normalizeEmail(body.email);
    const verificationToken = String(body.emailVerificationToken || '');
    const addressFlat = String(body.addressFlat || '').trim().slice(0, 80);
    const addressBuilding = String(body.addressBuilding || '').trim().slice(0, 120);
    const addressStreet = String(body.addressStreet || '').trim().slice(0, 160);
    const pincode = String(body.pincode || '').trim();
    const addressLandmark = String(body.addressLandmark || '').trim().slice(0, 160);
    const googleMapsUrl = String(body.googleMapsUrl || '').trim().slice(0, 500);
    const password = String(body.password || '');
    const confirmPassword = String(body.confirmPassword || '');

    if (firstName.length < 1 || lastName.length < 1) return send(res, 400, { error: 'Enter your first and last name.' });
    if (password.length < 8 || password.length > 128) return send(res, 400, { error: 'Use a password between 8 and 128 characters.' });
    if (password !== confirmPassword) return send(res, 400, { error: 'Your passwords do not match.' });
    if (!['West Bengal', 'Odisha'].includes(body.state) || body.state !== 'West Bengal' || body.city !== 'Kolkata') {
      return send(res, 400, { error: 'At the moment, we deliver only in Kolkata, West Bengal.' });
    }
    if (!validEmail(email) || !/^[^\s@]+@gmail\.com$/i.test(email)) return send(res, 400, { error: 'Enter a valid Gmail address.' });
    const emailProof = verifiedEmailTokens.get(verificationToken);
    const isStatelessValid = verifyStatelessVerificationToken(verificationToken, email);
    const isMemoryValid = Boolean(emailProof && emailProof.email === email && emailProof.expiresAt >= Date.now());
    if (!isStatelessValid && !isMemoryValid) return send(res, 400, { error: 'Verify your email address before creating your account.' });
    if (!validPhone(phone)) return send(res, 400, { error: 'Enter your phone number with country code.' });
    if (addressFlat.length < 1 || addressBuilding.length < 2 || addressStreet.length < 2 || !/^\d{6}$/.test(pincode)) {
      return send(res, 400, { error: 'Enter your flat or house number, building, street or area, and six-digit PIN code.' });
    }
    if (!validMapsUrl(googleMapsUrl)) return send(res, 400, { error: 'Use a Google Maps link beginning with https://.' });

    const existing = await db.findUserByIdentifier(null, { phone, email });
    if (existing) return send(res, 409, { error: 'An account already uses that phone number or email. Sign in instead.' });

    const credentials = await hashPassword(password);
    const user = {
      id: crypto.randomUUID(),
      firstName,
      lastName,
      phone,
      phoneVerified: false,
      email,
      state: 'West Bengal',
      city: 'Kolkata',
      addressFlat,
      addressBuilding,
      addressStreet,
      pincode,
      addressLandmark,
      googleMapsUrl,
      passwordSalt: credentials.salt,
      passwordHash: credentials.hash,
      createdAt: new Date().toISOString(),
    };

    await db.createUser(user);
    verifiedEmailTokens.delete(verificationToken);

    const session = await issueSession(user);
    return send(res, 201, { user: publicUser(user), token: session.token }, { 'Set-Cookie': session.cookie });
  }

  // POST /api/auth/signin
  if (req.method === 'POST' && url.pathname === '/api/auth/signin') {
    if (!rateLimit(`signin:${ip}`, 12, 10 * 60 * 1000)) {
      return send(res, 429, { error: 'Too many sign-in attempts. Try again later.' });
    }

    let body;
    try { body = await readJson(req); }
    catch (err) { return send(res, err.status || 400, { error: err.message }); }

    const identifier = String(body.identifier || '').trim();
    const phone = normalizePhone(identifier);
    const email = normalizeEmail(identifier);

    const user = await db.findUserByIdentifier(null, { phone, email });

    const salt = user?.passwordSalt || 'deepora-invalid-account-salt';
    const expected = user?.passwordHash || '00'.repeat(64);
    const candidate = await hashPassword(String(body.password || ''), salt);
    const matches = candidate.hash.length === expected.length && crypto.timingSafeEqual(Buffer.from(candidate.hash, 'hex'), Buffer.from(expected, 'hex'));

    if (!user || !matches) {
      return send(res, 401, { error: 'That phone/email and password combination was not found.' });
    }

    const session = await issueSession(user);
    return send(res, 200, { user: publicUser(user), token: session.token }, { 'Set-Cookie': session.cookie });
  }

function getBackendStatusHtml(isDbConnected, lastErr) {
  const dbStatusClass = isDbConnected ? 'status-online' : 'status-warn';
  const dbStatusText = isDbConnected ? 'MongoDB Atlas Connected' : 'Database Offline';
  const platform = process.env.VERCEL ? 'Vercel Serverless' : 'Node.js Production';
  const isMissingEnv = !process.env.MONGODB_URI;
  const errorReason = lastErr || (isMissingEnv ? 'MONGODB_URI is not set in Vercel Environment Variables' : 'Could not reach MongoDB Atlas cluster');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Deepora Backend is running</title>
  <meta name="description" content="Deepora Storefront REST API and Database Service">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Playfair+Display:ital,wght@0,600;1,600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0907;
      --card-bg: rgba(22, 17, 13, 0.85);
      --card-border: rgba(212, 163, 89, 0.22);
      --card-border-glow: rgba(224, 109, 83, 0.35);
      --text: #f7ede2;
      --text-muted: #bdaea1;
      --gold: #d4a359;
      --flame: #e06d53;
      --emerald: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      background-image: 
        radial-gradient(circle at 50% 15%, rgba(224, 109, 83, 0.18), transparent 45%),
        radial-gradient(circle at 85% 75%, rgba(212, 163, 89, 0.12), transparent 40%),
        radial-gradient(circle at 15% 85%, rgba(224, 109, 83, 0.08), transparent 35%);
      color: var(--text);
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px;
      line-height: 1.6;
    }
    .wrapper {
      max-width: 680px;
      width: 100%;
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 44px 36px;
      box-shadow: 0 24px 60px -12px rgba(0, 0, 0, 0.65), 0 0 40px -10px var(--card-border-glow);
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, transparent, var(--gold), var(--flame), transparent);
    }
    .diya-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(224, 109, 83, 0.25) 0%, rgba(212, 163, 89, 0.08) 100%);
      border: 1px solid rgba(212, 163, 89, 0.35);
      margin-bottom: 20px;
      box-shadow: 0 0 25px rgba(224, 109, 83, 0.35);
    }
    .diya-icon {
      width: 32px;
      height: 32px;
      fill: none;
      stroke: var(--gold);
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .pulse-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      border-radius: 999px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.02em;
      margin-bottom: 16px;
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--emerald);
      box-shadow: 0 0 10px var(--emerald);
      animation: pulse 2s infinite ease-in-out;
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.35); opacity: 0.6; }
    }
    h1 {
      font-family: 'Playfair Display', Georgia, serif;
      font-size: 34px;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: #fff;
      margin-bottom: 10px;
    }
    h1 span {
      background: linear-gradient(135deg, #f7ede2, var(--gold));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 15px;
      color: var(--text-muted);
      max-width: 480px;
      margin: 0 auto 30px;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
      text-align: left;
    }
    .meta-item {
      background: rgba(12, 9, 7, 0.65);
      border: 1px solid rgba(212, 163, 89, 0.15);
      border-radius: 14px;
      padding: 14px 16px;
    }
    .meta-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .meta-value {
      font-size: 13.5px;
      font-weight: 600;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .status-online { color: #34d399; }
    .status-warn { color: #fbbf24; }
    .alert-box {
      margin: 0 0 24px;
      padding: 18px 20px;
      background: rgba(245, 158, 11, 0.08);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 14px;
      text-align: left;
    }
    .alert-header {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #fbbf24;
      font-weight: 700;
      font-size: 14px;
      margin-bottom: 8px;
    }
    .alert-reason {
      font-size: 13px;
      color: #f7ede2;
      margin-bottom: 12px;
      word-break: break-word;
    }
    .alert-reason code {
      background: rgba(0,0,0,0.5);
      padding: 3px 8px;
      border-radius: 6px;
      color: #fca5a5;
      font-family: monospace;
      font-size: 12px;
    }
    .alert-steps {
      font-size: 12.5px;
      color: var(--text-muted);
      line-height: 1.6;
    }
    .alert-steps ol {
      margin-left: 20px;
      margin-top: 6px;
    }
    .alert-steps li {
      margin-bottom: 4px;
    }
    .endpoints-title {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--gold);
      margin-bottom: 12px;
    }
    .endpoints-list {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 10px;
    }
    .endpoint-btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      background: rgba(212, 163, 89, 0.08);
      border: 1px solid rgba(212, 163, 89, 0.22);
      border-radius: 12px;
      color: var(--text);
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
      font-family: monospace;
      transition: all 0.2s ease;
    }
    .endpoint-btn:hover {
      background: rgba(212, 163, 89, 0.18);
      border-color: var(--gold);
      transform: translateY(-1px);
    }
    .method {
      background: rgba(224, 109, 83, 0.2);
      color: #ff9d85;
      padding: 2px 6px;
      border-radius: 6px;
      font-size: 11px;
    }
    .footer {
      text-align: center;
      margin-top: 24px;
      font-size: 12px;
      color: rgba(189, 174, 161, 0.65);
    }
    .footer a {
      color: var(--gold);
      text-decoration: none;
    }
    .footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="diya-badge">
        <svg class="diya-icon" viewBox="0 0 24 24">
          <path d="M12 2c.5 2 2.5 4 2.5 6a2.5 2.5 0 0 1-5 0c0-2 2-4 2.5-6z" fill="var(--flame)" stroke="none"/>
          <path d="M4 14c0 4.418 3.582 7 8 7s8-2.582 8-7c0-2-2-4-8-4s-8 2-8 4z"/>
          <path d="M7 14h10"/>
        </svg>
      </div>

      <div class="pulse-pill">
        <span class="pulse-dot"></span>
        Deepora Service Online
      </div>

      <h1><span>Deepora Backend is running</span></h1>
      <p class="subtitle">REST API & MongoDB database service powering the handcrafted Deepora storefront.</p>

      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Environment</div>
          <div class="meta-value">${platform}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Database</div>
          <div class="meta-value ${dbStatusClass}">● ${dbStatusText}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Service Version</div>
          <div class="meta-value">v1.0.0 (REST)</div>
        </div>
      </div>

      ${!isDbConnected ? `
      <div class="alert-box">
        <div class="alert-header">
          <span>⚠️</span>
          <span>MongoDB Database Disconnected</span>
        </div>
        <p class="alert-reason">Diagnostic: <code>${escapeHtml(errorReason)}</code></p>
        <div class="alert-steps">
          <strong>How to fix on Vercel:</strong>
          <ol>
            ${isMissingEnv ? `
              <li>Open your <strong>Vercel Dashboard</strong> &rarr; Select your backend project.</li>
              <li>Go to <strong>Settings</strong> &rarr; <strong>Environment Variables</strong>.</li>
              <li>Add Key: <code>MONGODB_URI</code> with your MongoDB Atlas connection string.</li>
              <li>Go to the <strong>Deployments</strong> tab &rarr; Click <strong>Redeploy</strong>.</li>
            ` : `
              <li>Open <a href="https://cloud.mongodb.com" target="_blank" style="color:var(--gold);text-decoration:underline;">MongoDB Atlas</a> &rarr; <strong>Network Access</strong>.</li>
              <li>Click <strong>Add IP Address</strong> &rarr; Choose <strong>Allow Access from Anywhere</strong> (<code>0.0.0.0/0</code>) &rarr; Click <strong>Confirm</strong>. (Required for dynamic Vercel serverless IPs).</li>
              <li>Verify your database user password in Atlas &rarr; <strong>Database Access</strong>.</li>
            `}
          </ol>
        </div>
      </div>
      ` : ''}

      <div class="endpoints-title">Live API Endpoints</div>
      <div class="endpoints-list">
        <a class="endpoint-btn" href="/api/products" target="_blank">
          <span class="method">GET</span> /api/products
        </a>
        <a class="endpoint-btn" href="/api/health" target="_blank">
          <span class="method">GET</span> /api/health
        </a>
        <a class="endpoint-btn" href="/api/health/email" target="_blank">
          <span class="method">GET</span> /api/health/email
        </a>
        <a class="endpoint-btn" href="/?format=json" target="_blank">
          <span class="method">JSON</span> Status API
        </a>
      </div>
    </div>

    <div class="footer">
      Deepora Storefront · Handcrafted Festive Diyas · <a href="/api/health">Diagnostic Status</a>
    </div>
  </div>
</body>
</html>`;
}

  // Root API Information & Web Preview
  if ((url.pathname === '/' || url.pathname === '/api') && (req.method === 'GET' || req.method === 'HEAD')) {
    const wantsJson = (req.headers.accept && req.headers.accept.includes('application/json') && !req.headers.accept.includes('text/html')) ||
      url.searchParams.get('format') === 'json' ||
      url.pathname === '/api';

    if (wantsJson) {
      const isDbConnected = db.isConnected();
      return send(res, 200, {
        service: 'DEEPORA REST API',
        message: 'Deepora Backend is running',
        status: 'online',
        database: isDbConnected ? 'connected' : 'offline',
        ...(isDbConnected ? {} : { databaseError: db.getLastMongoError() || 'MongoDB offline' }),
        version: '1.0.0',
        platform: process.env.VERCEL ? 'Vercel Serverless' : 'Node.js Standalone',
        documentation: 'See README.md for endpoint specifications',
        endpoints: {
          health: '/api/health',
          healthEmail: '/api/health/email',
          products: '/api/products',
          authMe: '/api/auth/me',
          cart: '/api/cart',
          orders: '/api/orders',
        },
      });
    }

    // Render HTML preview for web browsers and Vercel web preview
    const isDbConnected = db.isConnected();
    const lastErr = db.getLastMongoError();
    const html = getBackendStatusHtml(isDbConnected, lastErr);
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    });
    if (req.method === 'HEAD') return res.end();
    return res.end(html);
  }

  // Optional static file serving if configured or if static folder exists
  if (req.method === 'GET' || req.method === 'HEAD') {
    let filePath = url.pathname;
    if (filePath === '/checkout') filePath = '/checkout.html';
    else if (filePath === '/account') filePath = '/account.html';

    const frontendCandidates = [
      process.env.FRONTEND_STATIC_DIR,
      path.resolve(__dirname, '..', 'public'),
      path.resolve(__dirname, '..', '..', 'Deepora-FrontEnd'),
    ].filter(Boolean);

    for (const frontendRoot of frontendCandidates) {
      const safePath = path.resolve(frontendRoot, `.${filePath}`);
      if (safePath.startsWith(frontendRoot + path.sep)) {
        try {
          const stats = await fs.stat(safePath);
          if (stats.isFile()) {
            const ext = path.extname(safePath).toLowerCase();
            const contentType = MIME_TYPES[ext] || 'application/octet-stream';
            const rangeHeader = req.headers.range;
            if (rangeHeader && contentType.startsWith('video/')) {
              const match = rangeHeader.match(/^bytes=(\d*)-(\d*)$/);
              if (!match || (!match[1] && !match[2])) {
                res.writeHead(416, { 'Content-Range': `bytes */${stats.size}` });
                return res.end();
              }
              const start = match[1] ? Number(match[1]) : Math.max(0, stats.size - Number(match[2]));
              const end = match[2] && match[1] ? Math.min(Number(match[2]), stats.size - 1) : stats.size - 1;
              if (start >= stats.size || start > end) {
                res.writeHead(416, { 'Content-Range': `bytes */${stats.size}` });
                return res.end();
              }
              res.writeHead(206, {
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'public, max-age=3600',
                'Content-Length': end - start + 1,
                'Content-Range': `bytes ${start}-${end}/${stats.size}`,
                'Content-Type': contentType,
              });
              if (req.method === 'HEAD') return res.end();
              return fsSync.createReadStream(safePath, { start, end }).pipe(res);
            }
            res.writeHead(200, {
              'Content-Type': contentType,
              ...(contentType.startsWith('video/') ? { 'Accept-Ranges': 'bytes' } : {}),
              'Content-Length': stats.size,
              'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
            });
            if (req.method === 'HEAD') return res.end();
            return fsSync.createReadStream(safePath).pipe(res);
          }
        } catch {}
      }
    }
  }

  return send(res, 404, { error: 'Not found.' });
}

async function start() {
  const server = http.createServer((req, res) => {
    handle(req, res).catch(error => {
      console.error('Request failed:', error);
      if (!res.headersSent) send(res, 500, { error: 'The service encountered an unexpected problem.' });
      else res.end();
    });
  });

  server.listen(port, host, () => {
    console.log(`Deepora server running at http://${host}:${port}`);
    console.log(`Database: ${db.isConnected() ? 'MongoDB (connected)' : 'connecting...'}`);
  });

  try {
    await db.connectToMongo();
    console.log('[MongoDB] Database connected successfully. Database-backed API routes are ready.');
  } catch (error) {
    console.warn(`[MongoDB] Initial connection failed, running in offline mode: ${error.message}`);
    mongoRetryTimer = setInterval(async () => {
      if (db.isConnected()) {
        clearInterval(mongoRetryTimer);
        mongoRetryTimer = null;
        console.log('[MongoDB] Reconnected. Database-backed API routes are available.');
        return;
      }
      try {
        await db.connectToMongo();
        clearInterval(mongoRetryTimer);
        mongoRetryTimer = null;
        console.log('[MongoDB] Reconnected. Database-backed API routes are available.');
      } catch (retryError) {
        console.warn(`[MongoDB] Retry failed: ${retryError.message}`);
      }
    }, 30000);
    mongoRetryTimer.unref();
  }
}

module.exports = handle;
module.exports.handle = handle;
module.exports.start = start;

if (require.main === module) {
  start().catch(error => {
    console.error('Server could not start:', error);
    process.exitCode = 1;
  });
}
