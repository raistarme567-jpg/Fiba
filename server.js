/**
 * ============================================================================
 * FLAME_CLOUD (FIBA — Future Integration & Backup Architecture)
 * Backend Module 5: Standalone Node.js / Express Server (backend/server.js)
 * ============================================================================
 * Serves `../frontend` static UI files and exposes REST endpoints alongside
 * the PHP/MySQL backend (`db.php`, `auth.php`, `upload.php`).
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const db = {
  accountQuota: { email: 'architect@fiba', maxProjectsLimit: 2 },
  projects: [
    { projectId: 'fiba-core-prod', name: 'Fiba Core Platform', env: 'PRODUCTION' },
    { projectId: 'fiba-commerce-stg', name: 'Fiba Commerce Sandbox', env: 'STAGING' }
  ],
  garageRequests: new Map()
};

function sha256(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

app.post('/v1/garage/step1-send-otp', (req, res) => {
  const { mobileNumber, emailAddress } = req.body || {};
  if (!mobileNumber || !emailAddress || !emailAddress.includes('@')) {
    return res.status(400).json({ error: 'Valid mobileNumber and emailAddress required' });
  }
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const requestId = 'grg_' + crypto.randomBytes(3).toString('hex');
  db.garageRequests.set(requestId, {
    requestId,
    mobileNumber,
    emailAddress,
    otpCodeHash: sha256(otp),
    otpVerified: false,
    fullName: '',
    fibaId: '',
    currentProjectLimit: db.accountQuota.maxProjectsLimit,
    requestedProjectLimit: db.accountQuota.maxProjectsLimit + 5,
    status: 'OTP_PENDING',
    statusNotice: 'Your request will be processed within 24 hours.',
    createdAt: Date.now()
  });
  res.json({ requestId, step: 2, dispatchedOtpPreview: otp });
});

app.post('/v1/garage/step2-verify-otp', (req, res) => {
  const { requestId, otp } = req.body || {};
  const record = db.garageRequests.get(requestId);
  if (!record) return res.status(404).json({ error: 'Request not found' });
  if (sha256(otp) !== record.otpCodeHash) {
    return res.status(401).json({ error: 'INVALID_OTP' });
  }
  record.otpVerified = true;
  record.status = 'OTP_VERIFIED';
  res.json({
    requestId,
    otpVerified: true,
    step: 3,
    notice: 'Your request will be processed within 24 hours.'
  });
});

app.post('/v1/garage/step3-submit', (req, res) => {
  const { requestId, fullName, fibaId } = req.body || {};
  const record = db.garageRequests.get(requestId);
  if (!record || !record.otpVerified) {
    return res.status(403).json({ error: 'OTP verification required before Step 3' });
  }
  const handlePrefix = String(fibaId || 'user').toLowerCase().split('@')[0].replace(/[^a-z0-9_.-]/g, '');
  record.fullName = fullName;
  record.fibaId = `${handlePrefix}@fiba`;
  record.status = 'PENDING_ADMIN';
  res.status(201).json({
    requestId,
    status: record.status,
    fullName: record.fullName,
    fibaId: record.fibaId,
    notice: 'Your request will be processed within 24 hours.',
    forwardedToAdminPanel: true
  });
});

const PORT = process.env.PORT || 8088;
app.listen(PORT, () => console.log(`FLAME_CLOUD Backend Server listening on http://127.0.0.1:${PORT}`));
