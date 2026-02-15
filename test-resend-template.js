require('dotenv').config();
const { Resend } = require('resend');

const code = '123456';
const brandName = 'Koun';
const brandLogo = process.env.EMAIL_LOGO_URL;

const kawnPremiumTemplate = `
  <!DOCTYPE html>
  <html dir="rtl" lang="ar">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body style="margin: 0; padding: 0; font-family: 'Cairo', 'Segoe UI', Tahoma, Arial, sans-serif; background: linear-gradient(180deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); min-height: 100vh;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background: linear-gradient(180deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); padding: 40px 20px;">
      <tr>
        <td align="center">
          <table width="600" cellpadding="0" cellspacing="0" style="background: linear-gradient(145deg, rgba(30,41,59,0.95) 0%, rgba(15,23,42,0.98) 100%); border-radius: 24px; overflow: hidden; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5), 0 0 0 1px rgba(6,182,212,0.1); border: 1px solid rgba(6,182,212,0.2);">
            <tr>
              <td style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); padding: 50px 40px; text-align: center; border-bottom: 1px solid rgba(6,182,212,0.2);">
                <div style="display: inline-block; padding: 20px; background: linear-gradient(145deg, rgba(6,182,212,0.1) 0%, rgba(6,182,212,0.05) 100%); border-radius: 20px; border: 1px solid rgba(6,182,212,0.2); box-shadow: 0 0 40px rgba(6,182,212,0.2);">
                  <img src="${brandLogo}" alt="كون Logo" style="max-width: 120px; height: auto;" />
                </div>
                <h1 style="color: #ffffff; margin: 25px 0 0 0; font-size: 48px; font-weight: 800;">كـون</h1>
              </td>
            </tr>
            <tr>
              <td style="padding: 50px 40px; color: #ffffff;">
                <h2 style="text-align: center;">رمز التحقق الخاص بك هو: ${code}</h2>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
  </html>
`;

async function testResendTemplate() {
  const resend = new Resend(process.env.RESEND_API_KEY);
  try {
    const data = await resend.emails.send({
      from: `Koun <${process.env.RESEND_FROM}>`,
      to: 'abdelrazikehab1@gmail.com',
      subject: 'Resend Template Test',
      html: kawnPremiumTemplate,
    });
    console.log('✅ Resend success:', data);
  } catch (error) {
    console.error('❌ Resend failed:', error.message);
  }
}

testResendTemplate();
