import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { EmailService } from './email/email.service';

@Controller()
export class AppController {
  constructor(private readonly emailService: EmailService) {}

  @Get()
  @SkipThrottle()
  getHealth() {
    return {
      success: true,
      service: 'app-auth',
      status: 'running',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('health')
  @SkipThrottle()
  health() {
    return {
      success: true,
      service: 'auth',
      status: 'healthy',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('health/email/test')
  @SkipThrottle()
  async testEmail() {
    try {
      const testEmail = process.env.TEST_EMAIL || 'abdelrazikehab7@gmail.com';
      const resendApiKey = process.env.RESEND_API_KEY;
      
      if (!resendApiKey) {
        return {
          success: false,
          error: 'RESEND_API_KEY not configured',
        };
      }

      const { Resend } = await import('resend');
      const resend = new Resend(resendApiKey);
      
      const fromEmail = process.env.RESEND_FROM || 'no-reply@kounworld.com';
      
      const result: any = await (resend as any).emails.send({
        from: `Test <${fromEmail}>`,
        to: testEmail,
        subject: 'Test Email from Kounstack',
        html: '<h1>Test Email</h1><p>If you receive this, Resend is working correctly!</p>',
      });

      if (!result || result.error) {
        const errorMsg = result?.error?.message || 'Unknown Resend error or empty response';
        return {
          success: false,
          error: errorMsg,
          details: result?.error || result,
        };
      }

      return {
        success: true,
        message: 'Test email sent successfully',
        messageId: result.id || result.data?.id || 'resend',
        from: fromEmail,
        to: testEmail,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || String(error),
        details: {
          code: error.code,
          statusCode: error.statusCode,
          response: error.response || error.data,
        },
      };
    }
  }

  @Get('health/email')
  @SkipThrottle()
  emailHealth() {
    const hasResend = !!process.env.RESEND_API_KEY;
    const hasSmtp = !!(process.env.SMTP_USER && process.env.SMTP_PASS);
    const resendFrom = process.env.RESEND_FROM || 'onboarding@resend.dev';
    const smtpUser = process.env.SMTP_USER || '';
    const smtpHost = process.env.SMTP_HOST || '';
    
    // Mask sensitive information
    const maskedSmtpUser = smtpUser ? (smtpUser.includes('@') 
      ? smtpUser.split('@')[0].substring(0, 3) + '...@' + smtpUser.split('@')[1]
      : smtpUser.substring(0, 3) + '...') : 'NOT SET';
    
    const resendKeyStatus = hasResend 
      ? `SET (starts with ${process.env.RESEND_API_KEY?.substring(0, 5)}...)`
      : 'NOT SET';
    
    return {
      success: true,
      email: {
        resend: {
          configured: hasResend,
          apiKey: resendKeyStatus,
          fromEmail: resendFrom,
          note: resendFrom === 'onboarding@resend.dev' 
            ? '⚠️ Using default Resend email. This ONLY works for sending to your verified email address.'
            : '✅ Using custom Resend sender email',
        },
        smtp: {
          configured: hasSmtp,
          user: maskedSmtpUser,
          host: smtpHost || 'NOT SET',
          port: process.env.SMTP_PORT || 'NOT SET',
          note: hasSmtp 
            ? '✅ SMTP credentials configured'
            : '⚠️ SMTP credentials NOT configured',
        },
        status: hasResend || hasSmtp 
          ? '✅ Email service configured (at least one method available)'
          : '❌ Email service NOT configured (both Resend and SMTP are missing)',
        recommendation: !hasResend && !hasSmtp
          ? 'Configure either RESEND_API_KEY or SMTP_USER + SMTP_PASS environment variables'
          : !hasResend
          ? 'Consider adding RESEND_API_KEY for better email delivery'
          : !hasSmtp
          ? 'Consider adding SMTP credentials as fallback'
          : '✅ Both Resend and SMTP configured - good redundancy',
      },
      timestamp: new Date().toISOString(),
    };
  }
}

