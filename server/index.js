// IdenTT local backend — the ONLY piece of this project that holds real SMTP/Twilio credentials.
// Exists because browsers cannot open raw SMTP sockets, and cannot safely call the Twilio REST API
// directly (that requires an Auth Token, which must never ship to client-side JS). This server
// reads its credentials from .env (copy .env.example — never commit the real file) and exposes two
// endpoints the browser app's src/dispatch/realDispatch.js calls over localhost.
//
// Run it with: cd server && npm install && npm start
//
// SECURITY NOTE: this is a small local convenience server meant to run on the SAME machine as the
// browser app, listening only on localhost, for a single local user. It has no authentication of
// its own — anything that can reach its port can send email/SMS through your configured accounts.
// Do not deploy this to a public host or expose its port beyond localhost without adding your own
// authentication layer first.

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import twilio from 'twilio';

const PORT = process.env.PORT || 4737;
const app = express();
app.use(cors());
app.use(express.json());

function getMailTransport() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: SMTP_SECURE === 'true',
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

function getTwilioClient() {
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN } = process.env;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN) return null;
  return twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
}

app.get('/health', (req, res) => {
  res.json({ ok: true, email: !!getMailTransport(), sms: !!getTwilioClient() });
});

app.post('/send-email', async (req, res) => {
  const { to, subject, text } = req.body || {};
  if (!to || !text) return res.status(400).json({ error: 'to and text are required' });
  const transport = getMailTransport();
  if (!transport) {
    return res
      .status(503)
      .json({ error: 'SMTP is not configured on this server — fill in server/.env (see .env.example) and restart.' });
  }
  try {
    const info = await transport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to,
      subject: subject || 'IdenTT request',
      text,
    });
    res.json({ ok: true, id: info.messageId });
  } catch (e) {
    res.status(502).json({ error: `SMTP send failed: ${e.message}` });
  }
});

app.post('/send-sms', async (req, res) => {
  const { to, body } = req.body || {};
  if (!to || !body) return res.status(400).json({ error: 'to and body are required' });
  const client = getTwilioClient();
  const from = process.env.TWILIO_FROM_NUMBER;
  if (!client || !from) {
    return res
      .status(503)
      .json({ error: 'Twilio is not configured on this server — fill in server/.env (see .env.example) and restart.' });
  }
  try {
    const message = await client.messages.create({ to, from, body });
    res.json({ ok: true, id: message.sid });
  } catch (e) {
    res.status(502).json({ error: `Twilio send failed: ${e.message}` });
  }
});

app.listen(PORT, () => {
  console.log(`IdenTT local backend listening on http://localhost:${PORT}`);
});
