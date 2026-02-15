const { Resend } = require('resend');
const dotenv = require('dotenv');
dotenv.config();

async function testResendSubject() {
  const resend = new Resend(process.env.RESEND_API_KEY);
  const brandName = 'تجربة';
  const fromEmail = process.env.RESEND_FROM || 'no-reply@saeaa.com';

  try {
    const data = await resend.emails.send({
      from: `Test <${fromEmail}>`,
      to: 'abdelrazikehab1@gmail.com',
      subject: `رمز التحقق - ${brandName}`,
      html: '<p>Testing Arabic subject.</p>',
    });
    console.log('✅ Resend success:', data);
  } catch (error) {
    console.error('❌ Resend failed:', error.message);
  }
}

testResendSubject();
