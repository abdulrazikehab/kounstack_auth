const { Resend } = require('resend');
const dotenv = require('dotenv');
dotenv.config();

async function testResend() {
  console.log('Testing Resend with:', process.env.RESEND_API_KEY);
  const resend = new Resend(process.env.RESEND_API_KEY);

  const brandName = 'تجربة كوني';
  const fromName = `"${brandName}"`;
  const fromEmail = process.env.RESEND_FROM || 'no-reply@saeaa.com';

  try {
    const data = await resend.emails.send({
      from: `${fromName} <${fromEmail}>`,
      to: 'abdelrazikehab1@gmail.com',
      subject: 'Resend Test with Quotes and Arabic',
      html: '<p>This is a test from Resend with quotes and Arabic name.</p>',
    });
    console.log('✅ Resend success:', data);
  } catch (error) {
    console.error('❌ Resend failed:', error.message);
  }
}

testResend();
