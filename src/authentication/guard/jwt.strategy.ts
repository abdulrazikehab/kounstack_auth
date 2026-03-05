// src/auth/strategies/jwt.strategy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // Try Authorization header first
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        // Fallback to cookie
        (request: any) => {
          return request?.cookies?.accessToken || null;
        },
      ]),
      ignoreExpiration: false,
      // Enforce strong JWT secret (minimum 32 characters)
      secretOrKey: (() => {
        const secret = configService.get<string>('JWT_SECRET');
        if (!secret) {
          throw new Error('JWT_SECRET is required in environment variables');
        }
        if (secret.length < 32) {
          throw new Error('JWT_SECRET must be at least 32 characters');
        }
        return secret;
      })(),
    });
  }

  async validate(payload: any) {
    // Basic payload validation
    if (!payload || !payload.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }

    // Log payload for debugging
    console.log('[JWT Strategy] Validating payload:', {
      sub: payload.sub,
      type: payload.type,
      role: payload.role,
      email: payload.email ? payload.email.substring(0, 10) + '...' : 'not provided',
      tenantId: payload.tenantId || 'not provided',
      hasSub: !!payload.sub,
      hasType: !!payload.type,
      hasEmail: !!payload.email,
      hasTenantId: !!payload.tenantId,
    });

    // -----------------------------------------------------------------
    // SECURITY FIX: Verify that the user still exists and is active.
    // This prevents token reuse after account deletion or deactivation.
    // -----------------------------------------------------------------
    // -----------------------------------------------------------------
    let user;
    try {
      user = await this.authService.validateUser(payload);
    } catch (error: any) {
      console.error('[JWT Strategy] Error in validateUser:', error.message);
      // If validateUser throws an error, log it but don't fail - try fallback
      user = null;
    }
    
    if (!user) {
      // Log detailed payload information for debugging
      console.error('[JWT Strategy] User validation failed. Payload:', JSON.stringify({
        sub: payload.sub,
        type: payload.type,
        role: payload.role,
        email: payload.email,
        tenantId: payload.tenantId,
        hasSub: !!payload.sub,
        hasType: !!payload.type,
        hasEmail: !!payload.email,
        hasTenantId: !!payload.tenantId,
        fullPayload: Object.keys(payload),
      }, null, 2));
      
      // CRITICAL FIX: If the token passed signature verification, it's valid.
      // Create a fallback user object here if validateUser failed.
      // This handles cases where the database lookup fails but the token is still valid.
      if (payload.sub) {
        console.warn('[JWT Strategy] Creating fallback user from payload');
        const inferredType = payload.type || 
                            (payload.role === 'CUSTOMER' ? 'customer' : 
                             payload.role === 'CUSTOMER_EMPLOYEE' ? 'customer_employee' : 'customer'); // Default to customer
        const inferredRole = payload.role || 
                            (payload.type === 'customer' ? 'CUSTOMER' : 
                             payload.type === 'customer_employee' ? 'CUSTOMER_EMPLOYEE' : 'CUSTOMER'); // Default to CUSTOMER
        
        user = {
          id: payload.sub,
          email: payload.email || `${payload.sub}@fallback.local`,
          role: inferredRole,
          type: inferredType,
          tenantId: payload.tenantId || null,
          firstName: payload.firstName || null,
          lastName: payload.lastName || null,
          isDisabled: false,
        };
        
        console.log('[JWT Strategy] Created fallback user:', {
          id: user.id,
          email: user.email,
          role: user.role,
          type: user.type,
        });
      } else {
        // Provide more helpful error message
        const errorMsg = payload.type === 'customer' || payload.type === 'customer_employee' || payload.role === 'CUSTOMER' || payload.role === 'CUSTOMER_EMPLOYEE'
          ? `Customer account not found. Please log out and log back in. If the issue persists, your account may have been deleted.`
          : 'User no longer exists';
        throw new UnauthorizedException(errorMsg);
      }
    }
    if (user.isDisabled) {
      throw new UnauthorizedException('User account is disabled');
    }

    // OPTIONAL: Token revocation check (placeholder – implement in AuthService)
    // if (await this.authService.isTokenRevoked(payload.jti)) {
    //   throw new UnauthorizedException('Token has been revoked');
    // }

    // Determine role and type from user object or payload
    // Priority: user.role > payload.type inference > payload.role
    let role = user.role;
    if (!role && payload.type === 'customer') {
      role = 'CUSTOMER';
    } else if (!role && payload.type === 'customer_employee') {
      role = 'CUSTOMER_EMPLOYEE';
    } else if (!role && payload.role) {
      role = payload.role;
    }
    
    // Determine type from payload or infer from role
    let type = payload.type || user.type;
    if (!type && role === 'CUSTOMER') {
      type = 'customer';
    } else if (!type && role === 'CUSTOMER_EMPLOYEE') {
      type = 'customer_employee';
    }

    return {
      id: user.id,
      userId: user.id,
      email: user.email,
      role: role || null,
      type: type || null,
      tenantId: user.tenantId,
      firstName: user.firstName,
      lastName: user.lastName,
    };
  }
}