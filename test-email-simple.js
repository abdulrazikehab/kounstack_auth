const { Resend } = require('resend');
const nodemailer = require('nodemailer');

const RESEND_API_KEY = 're_G4eb21Yu_BvL9hpirMhMP4PDrrqJ1sf1y';
const SMTP_USER = 'abdelrazikehab7@gmail.com';
const SMTP_PASS = 'hxnvrtutaftajptz';
const TO_EMAIL = 'abdelrazikehab1@gmail.com';

async function testResend() {
  console.log('--- Testing Resend ---');
  const resend = new Resend(RESEND_API_KEY);
  try {
    const data = await resend.emails.send({
      from: 'no-reply@saeaa.com',
      to: TO_EMAIL,
      subject: 'Resend Testsaeaa',
      html: 'This is a test from Resend Saeaa.',
    });
    console.log('Resend Success:', data);
  } catch (error) {
    console.error('Resend Error:', error.message);
  }
}

async function testSMTP() {
  console.log('--- Testing SMTP ---');
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
    tls: { rejectUnauthorized: false }
  });

  try {
    await transporter.verify();
    console.log('SMTP Verify Success');
    const info = await transporter.sendMail({
      from: `"Test Sender" <${SMTP_USER}>`,
      to: TO_EMAIL,
      subject: 'SMTP Test',
      text: 'This is a test from SMTP.',
    });
    console.log('SMTP Send Success:', info.messageId);
  } catch (error) {
    console.error('SMTP Error:', error.message);
  }
}

(async () => {
   await testResend();
   await testSMTP();
})();
