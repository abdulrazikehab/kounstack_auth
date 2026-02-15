const { Resend } = require('resend');
const dotenv = require('dotenv');
dotenv.config();

async function testResend() {
  console.log('Testing Resend with:', process.env.RESEND_API_KEY);
  const resend = new Resend(process.env.RESEND_API_KEY);

  try {
    const data = await resend.emails.send({
      from: `كون <${process.env.RESEND_FROM || 'no-reply@saeaa.com'}>`,
      to: 'abdelrazikehab1@gmail.com',
      subject: 'Resend Test with Arabic Name',
      html: '<p>This is a test from Resend with Arabic display name.</p>',
    });
    console.log('✅ Resend success:', data);
  } catch (error) {
    console.error('❌ Resend failed:', error.message);
  }
}

testResend();
