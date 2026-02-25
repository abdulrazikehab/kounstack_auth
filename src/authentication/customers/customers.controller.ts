// src/customers/customers.controller.ts
import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  ParseIntPipe,
  HttpCode,
  HttpStatus,
  Req,
  BadRequestException,
  ConflictException,
  UnauthorizedException,
  Logger,
  InternalServerErrorException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { JwtAuthGuard } from '../guard/jwt-auth.guard';
import { CustomersService, CreateCustomerDto, UpdateCustomerDto } from './customers.service';
import { PrismaService } from '../../prisma/prisma.service';

@Controller('customers')
export class CustomersController {
  private readonly logger = new Logger(CustomersController.name);

  constructor(
    private readonly customersService: CustomersService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Public endpoint for customer signup (storefront users)
   */
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async customerSignup(
    @Body() signupDto: { 
      email: string; 
      password: string; 
      firstName?: string; 
      lastName?: string; 
      phone?: string;
      storeName?: string;
      activity?: string;
      companyName?: string;
      city?: string;
      country?: string;
    },
    @Req() req: any,
  ) {
    try {
      // 1. Resolve tenant - PRIORITIZE HOST for strict isolation
      // Check Host header first to ensure we use the context of the domain being visited
      let tenantId: string | undefined;
      const host = req.headers.host || '';
      
      if (host && !host.includes('localhost:3001') && !host.includes('app-auth') && !host.includes('saeaa')) {
        const parts = host.split('.');
        if (parts.length > 2 || (host.includes('localhost') && parts.length > 1)) {
          tenantId = parts[0];
          this.logger.log(`🔍 Resolved tenantId=\"${tenantId}\" from Host header: ${host}`);
        }
      }

      // 2. Fallback to headers (X-Tenant-Id or X-Tenant-Domain)
      if (!tenantId || tenantId === 'default' || tenantId === 'www') {
        const rawHeaderTenant = (req.headers['x-tenant-id'] || req.headers['x-tenant-domain'] || req.headers['x-subdomain'] || req.tenantId);
        if (rawHeaderTenant) {
          const headerTenant = String(rawHeaderTenant);
          this.logger.log(`🔍 Processing header tenant: "${headerTenant}"`);
          
          // Handle localhost subdomain format (e.g., "kouncard.localhost:8080" or "kouncard.localhost")
          // This is the most common case for local development
          if (headerTenant.includes('.localhost')) {
            // Remove port if present (e.g., "kouncard.localhost:8080" -> "kouncard.localhost")
            const withoutPort = headerTenant.split(':')[0];
            // Extract subdomain (e.g., "kouncard.localhost" -> "kouncard")
            const localhostParts = withoutPort.split('.localhost');
            tenantId = localhostParts[0]; // Extract "kouncard" from "kouncard.localhost"
            this.logger.log(`🔍 Extracted subdomain from localhost domain "${headerTenant}": "${tenantId}"`);
          }
          // Handle production domain format (e.g., "kouncard.kounworld.com" or "kouncard.saeaa.com")
          else if (headerTenant.includes('.')) {
            const parts = headerTenant.split('.');
            // Extract subdomain (first part before the first dot)
            tenantId = parts[0];
            this.logger.log(`🔍 Extracted subdomain from domain "${headerTenant}": "${tenantId}"`);
          } else {
            tenantId = headerTenant;
            this.logger.log(`🔍 Using header tenant as-is: "${tenantId}"`);
          }
        }
      }
        
      if (tenantId && tenantId !== 'default') {
        try {
          // Clean up tenantId - remove any port numbers or localhost suffixes that might have been missed
          let cleanTenantId = String(tenantId);
          if (cleanTenantId.includes(':')) {
            cleanTenantId = cleanTenantId.split(':')[0]; // Remove port
          }
          if (cleanTenantId.includes('.localhost')) {
            cleanTenantId = cleanTenantId.split('.localhost')[0]; // Remove .localhost
          }
          
          let subdomain = cleanTenantId;
          if (cleanTenantId.includes('.')) {
            const parts = cleanTenantId.split('.');
            subdomain = parts[0] || cleanTenantId;
          }
          
          this.logger.log(`🔍 Looking up tenant with cleaned ID: "${cleanTenantId}", subdomain: "${subdomain}"`);
          
          const tenant = await this.prisma.tenant.findFirst({
            where: {
              OR: [
                { id: cleanTenantId },
                { subdomain: subdomain },
              ],
            },
          });
          
          if (tenant) {
            tenantId = tenant.id;
            this.logger.log(`✅ Successfully matched tenant: ${tenant.name} (${tenant.id}, subdomain: ${tenant.subdomain})`);
          } else {
            // STRICT: Reject signup if tenant not found
            this.logger.error(`❌ Signup rejected: Tenant "${cleanTenantId}" (subdomain: "${subdomain}") does not exist`);
            throw new BadRequestException(
              'Store not found. Please make sure you are accessing the correct store URL.'
            );
          }
        } catch (error: any) {
          if (error instanceof BadRequestException) {
            throw error; // Re-throw our own exception
          }
          this.logger.error(`❌ Error resolving tenant for signup:`, {
            error: error?.message || String(error),
            stack: error?.stack,
            tenantId,
          });
          throw new BadRequestException('Error resolving store. Please try again.');
        }
      }
      
      // STRICT: Reject if no tenant was resolved
      if (!tenantId || tenantId === 'default' || tenantId === 'null' || tenantId === 'undefined') {
        this.logger.error(`❌ Signup rejected: No valid tenant context provided (resolved: "${tenantId}")`);
        throw new BadRequestException(
          'Unable to determine which store you are trying to access. Please ensure you are on the correct store URL.'
        );
      }
      
      const ipAddress = req.ip || req.connection?.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
      this.logger.log(`🔍 Customer Signup Process: tenantId="${tenantId}", email="${signupDto?.email}", IP=${ipAddress}`);
      
      this.logger.log(`🚀 Calling customersService.customerSignup with tenantId: "${tenantId}"`);
      const result = await this.customersService.customerSignup(tenantId, signupDto, ipAddress);
      this.logger.log(`✅ Customer signup service call completed successfully`);
      return result;
    } catch (error: any) {
      this.logger.error(`❌ Customer signup error in controller (top-level catch):`, {
        error: error?.message || String(error),
        errorName: error?.name,
        errorCode: error?.code,
        stack: error?.stack,
        email: signupDto?.email,
      });
      
      // Re-throw known exceptions
      if (error instanceof BadRequestException || 
          error instanceof ConflictException || 
          error instanceof ForbiddenException ||
          error instanceof NotFoundException) {
        this.logger.log(`🔄 Re-throwing known exception: ${error.constructor.name}`);
        throw error;
      }
      
      // Prisma constraint/schema errors -> return 400 so user sees a clear message instead of 500
      const prismaCode = error?.code;
      if (typeof prismaCode === 'string' && (prismaCode.startsWith('P2') || prismaCode === 'P1001' || prismaCode === 'P1002')) {
        const msg = error?.meta?.target || error?.message || 'Invalid data. Please check your input and try again.';
        this.logger.warn(`Prisma error during signup (converted to 400): ${prismaCode}`, { message: error?.message });
        throw new BadRequestException(typeof msg === 'string' ? msg : 'Invalid data. Please check your input and try again.');
      }
      
      // For unknown errors, throw a more helpful error with the actual message
      const errorMessage = error?.message || 'Failed to complete signup. Please try again later.';
      this.logger.error(`❌ Throwing InternalServerErrorException with message: "${errorMessage}"`);
      throw new InternalServerErrorException(errorMessage);
    }
  }

  /**
   * Public endpoint for customer email verification (storefront users)
   */
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyCustomerEmail(
    @Body() verifyDto: { email: string; code: string },
    @Req() req: any,
  ) {
    // 1. Resolve tenant - PRIORITIZE HOST for strict isolation
    // Check Host header first to ensure we use the context of the domain being visited
    let tenantId: string | undefined;
    const host = req.headers.host || '';
    
    if (host && !host.includes('localhost:3001') && !host.includes('app-auth') && !host.includes('saeaa')) {
      const parts = host.split('.');
      if (parts.length > 2 || (host.includes('localhost') && parts.length > 1)) {
        tenantId = parts[0];
        this.logger.log(`🔍 Verify OTP - Resolved tenantId=\"${tenantId}\" from Host header: ${host}`);
      }
    }

    // 2. Fallback to headers (X-Tenant-Id or X-Tenant-Domain)
    if (!tenantId || tenantId === 'default' || tenantId === 'www') {
      const headerTenant = (req.headers['x-tenant-id'] || req.headers['x-tenant-domain'] || req.headers['x-subdomain'] || req.tenantId) as string;
      if (headerTenant) {
        // If headerTenant looks like a domain, extract subdomain
        if (headerTenant.includes('.')) {
          tenantId = headerTenant.split('.')[0];
        } else {
          tenantId = headerTenant;
        }
      }
    }

    this.logger.log(`🔍 Verify OTP - Request tenantId="${tenantId || 'default'}" for email: ${verifyDto.email}`);
    
    // Pass expectedTenantId for validation and logging
    return this.customersService.verifyCustomerSignupCode(verifyDto.email, verifyDto.code, tenantId);
  }

  /**
   * Public endpoint for resending customer verification code
   */
  @Post('resend-verification-code')
  @HttpCode(HttpStatus.OK)
  async resendCustomerVerificationCode(
    @Body() body: { email: string },
    @Req() req: any,
  ) {
    // 1. Resolve tenant - PRIORITIZE HOST for strict isolation
    let tenantId: string | undefined;
    const host = req.headers.host || '';
    
    if (host && !host.includes('localhost:3001') && !host.includes('app-auth') && !host.includes('saeaa')) {
      const parts = host.split('.');
      if (parts.length > 2 || (host.includes('localhost') && parts.length > 1)) {
        tenantId = parts[0];
      }
    }

    // 2. Fallback to headers
    if (!tenantId || tenantId === 'default' || tenantId === 'www') {
      const headerTenant = (req.headers['x-tenant-id'] || req.headers['x-tenant-domain'] || req.headers['x-subdomain'] || req.tenantId) as string;
      if (headerTenant) {
        if (headerTenant.includes('.')) {
          tenantId = headerTenant.split('.')[0];
        } else {
          tenantId = headerTenant;
        }
      }
    }

    return this.customersService.resendCustomerVerificationCode(body.email, tenantId);
  }

  /**
   * Public endpoint for sending OTP for invited customer
   */
  @Post('invite/send-otp')
  @HttpCode(HttpStatus.OK)
  async sendInviteOtp(@Body() body: { token: string }) {
    return this.customersService.sendInviteOtp(body.token);
  }

  /**
   * Public endpoint for verifying invited customer OTP
   */
  @Post('invite/verify')
  @HttpCode(HttpStatus.OK)
  async verifyInviteOtp(@Body() body: { token: string; code: string; password?: string }) {
    return this.customersService.verifyInviteOtp(body.token, body.code, body.password);
  }

  /**
   * Public endpoint for customer login (storefront users)
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async customerLogin(
    @Body() loginDto: { email: string; password: string },
    @Req() req: any,
  ) {
    try {
      this.logger.log('Customer login request received', { email: loginDto.email });
      
      // 1. Resolve tenant - PRIORITIZE HOST for strict isolation
      // Check Host header first to ensure we use the context of the domain being visited
      let tenantId: string | undefined;
      const host = req.headers.host || '';
      
      if (host && !host.includes('localhost:3001') && !host.includes('app-auth') && !host.includes('saeaa')) {
        const subdomain = host.split('.')[0];
        if (subdomain && subdomain !== 'localhost' && subdomain !== 'app' && subdomain !== 'www' && subdomain !== 'kawn' && subdomain !== 'api' && subdomain !== 'admin') {
          tenantId = subdomain;
          this.logger.log(`🔍 Resolved tenantId="${tenantId}" from Host header: ${host}`);
        }
      }

      // 2. Fallback to headers if Host didn't provide a specific tenant
      if (!tenantId || tenantId === 'default') {
        tenantId = req.headers['x-tenant-id'] 
          || req.headers['x-tenant-domain'] 
          || req.headers['x-subdomain']
          || req.tenantId;
      }

      if (tenantId && tenantId !== 'default' && tenantId !== 'null' && tenantId !== 'undefined') {
        try {
          // Clean up tenantId - handle potential domain suffix
          let cleanTenantId = String(tenantId);
          if (cleanTenantId.includes(':')) {
            cleanTenantId = cleanTenantId.split(':')[0]; // Remove port
          }
          if (cleanTenantId.includes('.localhost')) {
            cleanTenantId = cleanTenantId.split('.localhost')[0];
          }
          
          let subdomain = cleanTenantId;
          if (cleanTenantId.includes('.')) {
            const parts = cleanTenantId.split('.');
            subdomain = parts[0] || cleanTenantId;
          }
          
          this.logger.log(`🔍 Lookup tenant in login: id="${cleanTenantId}", subdomain="${subdomain}"`);
          
          const tenant = await this.prisma.tenant.findFirst({
            where: {
              OR: [
                { id: cleanTenantId },
                { subdomain: subdomain },
                { subdomain: cleanTenantId },
              ],
            },
          });
          
          if (tenant) {
            tenantId = tenant.id;
            this.logger.log(`✅ Matched tenant: ${tenant.name} (${tenant.id})`);
          } else {
            // STRICT: Reject login if tenant not found
            this.logger.error(`❌ Login rejected: Tenant "${cleanTenantId}" (subdomain: "${subdomain}") does not exist`);
            throw new BadRequestException(
              'Store not found. Please make sure you are accessing the correct store URL.'
            );
          }
        } catch (error: any) {
          if (error instanceof BadRequestException) {
            throw error; // Re-throw our own exception
          }
          this.logger.error(`Error resolving tenant for login: ${error.message}`);
          throw new BadRequestException('Error resolving store. Please try again.');
        }
      }
      
      // STRICT: Reject if no tenant was resolved
      if (!tenantId || tenantId === 'default' || tenantId === 'null' || tenantId === 'undefined') {
        this.logger.error(`❌ Login rejected: No valid tenant context provided`);
        throw new BadRequestException(
          'Unable to determine which store you are trying to access. Please ensure you are on the correct store URL.'
        );
      }
      
      const normalizedLoginDto = {
        email: loginDto.email?.toLowerCase().trim() || '',
        password: loginDto.password || '',
      };
      
      if (!normalizedLoginDto.email || !normalizedLoginDto.password) {
        throw new BadRequestException('Email and password are required');
      }
      
      this.logger.log(`🔍 Processing customer login: tenantId="${tenantId}", email="${normalizedLoginDto.email}"`);
      return await this.customersService.customerLogin(tenantId, normalizedLoginDto);
    } catch (error: any) {
      if (error instanceof BadRequestException || error instanceof UnauthorizedException) {
        throw error;
      }
      throw new BadRequestException(`Login failed: ${error.message || 'Unknown error occurred'}`);
    }
  }

  // Protected endpoints below (require JWT authentication)
  @Post()
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async createCustomer(
    @Request() req: any,
    @Body() createCustomerDto: CreateCustomerDto,
  ) {
    // Extract subdomain from request headers, JWT token, or hostname for invite URL
    let subdomain: string | undefined;
    let port: string | undefined;
    
    // Priority 1: Try to get subdomain and port from X-Tenant-Domain header (from frontend)
    const tenantDomainHeader = req.headers['x-tenant-domain'] as string;
    if (tenantDomainHeader) {
      // Extract subdomain and port from domain (e.g., "store.localhost:8080" -> "store" and "8080")
      const domainParts = tenantDomainHeader.split(':');
      const domainWithoutPort = domainParts[0];
      
      // Extract port if present
      if (domainParts.length > 1) {
        port = domainParts[1];
      }
      
      // Extract subdomain from domain
      if (domainWithoutPort.includes('.localhost')) {
        subdomain = domainWithoutPort.split('.localhost')[0];
      } else if (domainWithoutPort.endsWith('.kawn.com') || domainWithoutPort.endsWith('.kawn.net')) {
        const parts = domainWithoutPort.split('.');
        if (parts.length > 2 && parts[0] !== 'www' && parts[0] !== 'app') {
          subdomain = parts[0];
        }
      } else {
        // Try to extract subdomain from the first part
        const parts = domainWithoutPort.split('.');
        if (parts.length > 0 && parts[0] && parts[0] !== 'localhost' && parts[0] !== 'www' && parts[0] !== 'app') {
          subdomain = parts[0];
        }
      }
      
      this.logger.log(`📧 Extracted from X-Tenant-Domain header: subdomain=${subdomain}, port=${port}`);
    }
    
    // Priority 2: Try to get subdomain from JWT token (user.tenantSubdomain)
    if (!subdomain && req.user?.tenantSubdomain) {
      subdomain = req.user.tenantSubdomain;
    }
    
    // Priority 3: Try to extract from hostname (only if it's a subdomain, not the auth service)
    if (!subdomain) {
      const hostname = req.headers.host || '';
      const hostParts = hostname.split(':');
      const cleanHostname = hostParts[0];
      
      // Extract port if present
      if (hostParts.length > 1) {
        port = hostParts[1];
      }
      
      // Only extract subdomain if it's actually a subdomain (not localhost:3001 or similar)
      if (cleanHostname.includes('.localhost')) {
        subdomain = cleanHostname.split('.localhost')[0];
      } else if (cleanHostname.endsWith('.kawn.com') || cleanHostname.endsWith('.kawn.net')) {
        const parts = cleanHostname.split('.');
        if (parts.length > 2 && parts[0] !== 'www' && parts[0] !== 'app') {
          subdomain = parts[0];
        }
      }
    }
    
    // Note: If subdomain is still not found, it will be extracted from tenant record in service
    return this.customersService.createCustomer(req.user.tenantId, createCustomerDto, subdomain, port);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getCustomers(
    @Request() req: any,
    @Query('page', new ParseIntPipe({ optional: true })) page: number = 1,
    @Query('limit', new ParseIntPipe({ optional: true })) limit: number = 50,
    @Query('search') search?: string,
  ) {
    return this.customersService.getCustomers(req.user.tenantId, page, limit, search);
  }

  @Get('stats')
  @UseGuards(JwtAuthGuard)
  async getCustomerStats(@Request() req: any) {
    return this.customersService.getCustomerStats(req.user.tenantId);
  }

  @Get('email/:email')
  @UseGuards(JwtAuthGuard)
  async getCustomerByEmail(
    @Request() req: any,
    @Param('email') email: string,
  ) {
    return this.customersService.getCustomerByEmail(req.user.tenantId, email);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getCustomerById(
    @Request() req: any,
    @Param('id') customerId: string,
  ) {
    return this.customersService.getCustomerById(req.user.tenantId, customerId);
  }

  @Put('profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(
    @Request() req: any,
    @Body() updateCustomerDto: UpdateCustomerDto,
  ) {
    this.logger.log(`🔍 updateProfile called for user: ${JSON.stringify(req.user)}`);
    if (req.user.type !== 'customer' && req.user.role !== 'CUSTOMER') {
      throw new BadRequestException('This endpoint is only for customers');
    }
    
    // Use either id or userId from req.user
    const customerId = req.user.id || req.user.userId || req.user.sub;
    const tenantId = req.user.tenantId;
    
    return this.customersService.updateCustomer(tenantId, customerId, updateCustomerDto);
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard)
  async updateCustomer(
    @Request() req: any,
    @Param('id') customerId: string,
    @Body() updateCustomerDto: UpdateCustomerDto,
  ) {
    return this.customersService.updateCustomer(req.user.tenantId, customerId, updateCustomerDto);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteCustomer(
    @Request() req: any,
    @Param('id') customerId: string,
  ) {
    return this.customersService.deleteCustomer(req.user.tenantId, customerId);
  }

  @Post(':id/force-logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async forceLogoutCustomer(
    @Request() req: any,
    @Param('id') customerId: string,
  ) {
    return this.customersService.forceLogoutCustomer(req.user.tenantId, customerId);
  }

  @Put(':id/email-settings')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async updateCustomerEmailSettings(
    @Request() req: any,
    @Param('id') customerId: string,
    @Body('emailDisabled') emailDisabled: boolean,
  ) {
    return this.customersService.updateCustomerEmailSettings(req.user.tenantId, customerId, emailDisabled);
  }

  @Post('upsert')
  @UseGuards(JwtAuthGuard)
  async createOrUpdateCustomer(
    @Request() req: any,
    @Body() customerData: CreateCustomerDto,
  ) {
    return this.customersService.createOrUpdateCustomer(req.user.tenantId, customerData);
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(
    @Request() req: any,
    @Body() changePasswordDto: { currentPassword: string; newPassword: string },
  ) {
    if (req.user.type !== 'customer' && req.user.type !== 'customer_employee') {
      throw new BadRequestException('This endpoint is only for customers');
    }

    const customerId = req.user.id;
    return this.customersService.changePassword(
      customerId,
      changePasswordDto.currentPassword,
      changePasswordDto.newPassword,
    );
  }

  @Post('2fa/setup')
  @UseGuards(JwtAuthGuard)
  async setup2FA(@Request() req: any) {
    return this.customersService.setupTwoFactor(req.user.id);
  }

  @Post('2fa/setup-signup')
  @HttpCode(HttpStatus.OK)
  async setup2FADuringSignup(@Body() body: { email: string; verificationToken: string }) {
    return this.customersService.setupTwoFactorDuringSignup(body.email, body.verificationToken);
  }

  @Post('2fa/enable-signup')
  @HttpCode(HttpStatus.OK)
  async enable2FADuringSignup(@Body() body: { email: string; verificationToken: string; secret: string; code: string }) {
    return this.customersService.enableTwoFactorDuringSignup(body.email, body.verificationToken, body.secret, body.code);
  }

  @Post('2fa/enable')
  @UseGuards(JwtAuthGuard)
  async enable2FA(@Request() req: any, @Body() body: { secret: string; code: string }) {
    return this.customersService.enableTwoFactor(req.user.id, body.secret, body.code);
  }

  @Post('2fa/disable')
  @UseGuards(JwtAuthGuard)
  async disable2FA(@Request() req: any, @Body() body: { code: string }) {
    return this.customersService.disableTwoFactor(req.user.id, body.code);
  }

  @Post('login/2fa')
  @HttpCode(HttpStatus.OK)
  async verifyLogin2FA(@Body() body: { customerId: string; code: string }) {
    return this.customersService.verifyLogin2FA(body.customerId, body.code);
  }
}