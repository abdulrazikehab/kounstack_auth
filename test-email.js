const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

async function testEmail() {
  console.log('Testing SMTP with:', process.env.SMTP_USER);
  
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
    const info = await transporter.sendMail({
      from: `\"Test\" <${process.env.SMTP_USER}>`,
      to: 'abdelrazikehab942@gmail.com',
      subject: 'SMTP Test',
      text: 'This is a test email.',
    });
    console.log('✅ Email sent:', info.messageId);
  } catch (error) {
    console.error('❌ Email failed:', error.message);
  }
}

testEmail();
