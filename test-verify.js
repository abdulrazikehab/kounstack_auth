const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

async function testVerify() {
  console.log('Testing SMTP Verify with:', process.env.SMTP_USER);
  
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: {
      rejectUnauthorized: false
    }
  });

  try {
    console.log('Verifying...');
    await transporter.verify();
    console.log('✅ SMTP verified!');
  } catch (error) {
    console.error('❌ SMTP verification failed:', error.message);
  }
}

testVerify();
