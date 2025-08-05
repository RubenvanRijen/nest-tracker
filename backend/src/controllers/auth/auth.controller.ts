import {
    Controller,
    Post,
    Body,
    UsePipes,
    ValidationPipe,
    Get,
    Req,
    UseGuards,
    UnauthorizedException,
    HttpCode,
    Logger,
} from '@nestjs/common';
import {JwtAuthGuard} from '@backend/guards/auth/jwt-auth.guard';
import {RegisterDto} from '@backend/dto/auth/register.dto';
import {LoginDto} from '@backend/dto/auth/login.dto';
import {TwoFactorAuthVerifyDto} from '@backend/dto/auth/twofa-verify.dto';
import {TwoFactorAuthBackupDto} from '@backend/dto/auth/twofa-backup.dto';
import {RefreshTokenDto} from '@backend/dto/auth/refresh-token.dto';
import {AuthService} from '@backend/services/auth/auth.service';
import {TwoFaService} from '@backend/services/auth/twofa.service';
import type {IAuthRequest} from '@backend/interfaces/auth/IAuthRequest';
import {Throttle} from '@nestjs/throttler';
import {
    ApiTags,
    ApiOperation,
    ApiResponse,
    ApiBody,
    ApiBearerAuth,
    ApiUnauthorizedResponse,
    ApiForbiddenResponse,
    ApiCreatedResponse,
    ApiOkResponse,
} from '@nestjs/swagger';

/**
 * Rate limiting options for login attempts.
 * Allows 5 attempts per minute (60000ms).
 */
const loginThrottleOptions = {
    default: {limit: 5, ttl: 60000},
};

/**
 * Rate limiting options for two-factor authentication attempts.
 * Allows 5 attempts per minute (60000ms).
 */
const twoFaThrottleOptions = {
    default: {limit: 5, ttl: 60000},
};

@ApiTags('Authentication')
@Controller('auth')
@UsePipes(new ValidationPipe({whitelist: true}))
export class AuthController {
    private readonly logger = new Logger(AuthController.name);

    constructor(
        private readonly authService: AuthService,
        private readonly twoFaService: TwoFaService,
    ) {
    }

    @Post('register')
    @ApiOperation({summary: 'Register a new user'})
    @ApiBody({type: RegisterDto})
    @ApiCreatedResponse({
        description: 'User has been successfully registered',
        schema: {
            properties: {
                email: {type: 'string', example: 'user@example.com'},
                id: {type: 'string', example: '123e4567-e89b-12d3-a456-426614174000'},
                message: {type: 'string', example: 'Registration successful'}
            }
        }
    })
    @ApiResponse({status: 400, description: 'Bad request - validation error or user already exists'})
    async register(@Body() body: RegisterDto) {
        const user = await this.authService.registerUser(body.email, body.password);
        return {
            email: user.email,
            id: user.id,
            message: 'Registration successful',
        };
    }

    /**
     * Handles user login with email and password.
     * If 2FA is enabled, requires additional verification.
     * Otherwise, issues JWT and refresh tokens.
     */
    @Post('login')
    @Throttle(loginThrottleOptions)
    @ApiOperation({summary: 'Login with email and password'})
    @ApiBody({type: LoginDto})
    @ApiResponse({
        status: 201,
        description: 'Login successful',
        schema: {
            oneOf: [
                {
                    properties: {
                        email: {type: 'string', example: 'user@example.com'},
                        id: {type: 'string', example: '123e4567-e89b-12d3-a456-426614174000'},
                        token: {type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'},
                        refreshToken: {type: 'string', example: '6fd8d272-375a-4d8f-b7a3-248db6c56b48'},
                        message: {type: 'string', example: 'Login successful'},
                        twoFaEnabled: {type: 'boolean', example: false}
                    }
                },
                {
                    properties: {
                        message: {type: 'string', example: 'Two-factor authentication required'},
                        twoFaEnabled: {type: 'boolean', example: true},
                        email: {type: 'string', example: 'user@example.com'}
                    }
                }
            ]
        }
    })
    @ApiUnauthorizedResponse({description: 'Authentication failed'})
    async login(@Body() body: LoginDto) {
        const {user, jwt, refreshToken} = await this.authService.loginUser(
            body.email,
            body.password,
        );

        if (user.twoFaSecret) {
            return {
                message: 'Two-factor authentication required',
                twoFaEnabled: true,
                email: user.email,
            };
        }

        return {
            email: user.email,
            id: user.id,
            token: jwt,
            refreshToken,
            message: 'Login successful',
            twoFaEnabled: false,
        };
    }

    /**
     * Handles two-factor authentication login.
     * Verifies the 2FA token and issues JWT and refresh tokens if valid.
     */
    @Post('2fa/login')
    @Throttle(twoFaThrottleOptions)
    @HttpCode(200)
    @ApiOperation({summary: 'Login with 2FA token'})
    @ApiBody({type: TwoFactorAuthVerifyDto})
    @ApiOkResponse({
        description: '2FA verification successful',
        schema: {
            properties: {
                email: {type: 'string', example: 'user@example.com'},
                id: {type: 'string', example: '123e4567-e89b-12d3-a456-426614174000'},
                token: {type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'},
                refreshToken: {type: 'string', example: '6fd8d272-375a-4d8f-b7a3-248db6c56b48'},
                message: {type: 'string', example: 'Login successful'}
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Invalid 2FA token or 2FA not enabled'})
    async twoFaLogin(@Body() body: TwoFactorAuthVerifyDto) {
        const user = await this.authService.getUserByEmail(body.email);
        if (!user || !user.twoFaSecret) {
            this.logger.warn(`2FA login attempt for user without 2FA enabled: ${body.email}`);
            throw new UnauthorizedException('2FA not enabled for this user');
        }

        const decryptedSecret = this.twoFaService.decryptSecret(user.twoFaSecret);
        const valid = this.twoFaService.verify2faToken(decryptedSecret, body.token);

        if (!valid) {
            this.logger.warn(`Failed 2FA verification for user: ${user.id}`);
            throw new UnauthorizedException('Invalid 2FA token');
        }

        // Update last used timestamp
        user.twoFaLastUsed = new Date();
        await this.authService.saveUser(user);

        // Generate tokens
        const jwt = this.authService.generateJwt(user);
        const refreshToken = await this.authService.generateRefreshToken(user);

        this.logger.log(`Successful 2FA verification for user: ${user.id}`);
        return {
            email: user.email,
            id: user.id,
            token: jwt,
            refreshToken,
            message: 'Login successful',
        };
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/setup')
    @ApiOperation({summary: 'Setup 2FA for a user'})
    @ApiBearerAuth()
    @ApiCreatedResponse({
        description: '2FA setup initiated',
        schema: {
            properties: {
                secret: {type: 'string', example: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'},
                otpauthUrl: {type: 'string', example: 'otpauth://totp/NestTracker:user@example.com?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=NestTracker'}
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Unauthorized - valid JWT required'})
    async setup2fa(@Req() req: IAuthRequest) {
        const user = req.user;
        if (!user) throw new UnauthorizedException('User not found');
        const {secret, otpauthUrl} = this.twoFaService.generate2faSecret(
            user.email,
        );
        user.pendingTwoFaSecret = this.twoFaService.encryptSecret(secret);
        await this.authService.saveUser(user);
        this.logger.log(`2FA setup initiated for user: ${user.id}`);
        return {secret, otpauthUrl};
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/enable')
    @Throttle(twoFaThrottleOptions)
    @HttpCode(200)
    @ApiOperation({summary: 'Enable 2FA for a user'})
    @ApiBearerAuth()
    @ApiBody({type: TwoFactorAuthVerifyDto})
    @ApiOkResponse({
        description: '2FA successfully enabled',
        schema: {
            properties: {
                message: {type: 'string', example: '2FA enabled'}
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Unauthorized - invalid token or no pending setup'})
    async enable2fa(
        @Req() req: IAuthRequest,
        @Body() body: TwoFactorAuthVerifyDto,
    ) {
        const user = req.user;
        if (!user || typeof user.email !== 'string') {
            this.logger.warn(`2FA enable attempt with invalid user`);
            throw new UnauthorizedException('User not found');
        }
        if (!user.pendingTwoFaSecret) {
            this.logger.warn(`2FA enable attempt without pending setup for user: ${user.id}`);
            throw new UnauthorizedException('No pending 2FA setup found');
        }
        const decryptedSecret = this.twoFaService.decryptSecret(
            user.pendingTwoFaSecret,
        );
        const valid = this.twoFaService.verify2faToken(decryptedSecret, body.token);
        if (!valid) {
            this.logger.warn(`Failed 2FA enable verification for user: ${user.id}`);
            throw new UnauthorizedException('Invalid 2FA token');
        }
        user.twoFaSecret = user.pendingTwoFaSecret;
        user.pendingTwoFaSecret = undefined;
        await this.authService.saveUser(user);
        this.logger.log(`2FA successfully enabled for user: ${user.id}`);
        return {message: '2FA enabled'};
    }

    @UseGuards(JwtAuthGuard)
    @Get('2fa/status')
    @ApiOperation({summary: 'Get 2FA status for the current user'})
    @ApiBearerAuth()
    @ApiOkResponse({
        description: '2FA status',
        schema: {
            properties: {
                enabled: {type: 'boolean', example: true},
                lastUsed: {type: 'string', format: 'date-time', example: '2023-01-01T00:00:00Z'},
                pending: {type: 'boolean', example: false},
                hasBackupCodes: {type: 'boolean', example: true}
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Unauthorized - valid JWT required'})
    twofaStatus(@Req() req: IAuthRequest) {
        const user = req.user;
        return {
            enabled: !!(user && user.twoFaSecret),
            lastUsed: user?.twoFaLastUsed ?? null,
            pending: !!user?.pendingTwoFaSecret,
            hasBackupCodes: !!(user && user.twoFaBackupCodes && user.twoFaBackupCodes.length > 0),
        };
    }

    /**
     * Rotates a user's 2FA secret, generating a new one
     * Requires verification of the current 2FA token
     */
    @UseGuards(JwtAuthGuard)
    @Post('2fa/rotate')
    @Throttle(twoFaThrottleOptions)
    @HttpCode(200)
    @ApiOperation({summary: 'Rotate 2FA secret'})
    @ApiBearerAuth()
    @ApiBody({type: TwoFactorAuthVerifyDto})
    @ApiOkResponse({
        description: '2FA secret rotated successfully',
        schema: {
            properties: {
                message: {type: 'string', example: '2FA secret rotated successfully'},
                secret: {type: 'string', example: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'},
                otpauthUrl: {type: 'string', example: 'otpauth://totp/NestTracker:user@example.com?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=NestTracker'}
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Unauthorized - invalid token or 2FA not enabled'})
    async rotate2fa(
        @Req() req: IAuthRequest,
        @Body() body: TwoFactorAuthVerifyDto,
    ) {
        const user = req.user;
        if (!user || typeof user.email !== 'string') {
            this.logger.warn(`2FA rotation attempt with invalid user`);
            throw new UnauthorizedException('User not found');
        }

        if (!user.twoFaSecret) {
            this.logger.warn(`2FA rotation attempt for user without 2FA enabled: ${user.id}`);
            throw new UnauthorizedException('2FA not enabled for this user');
        }

        // Verify current 2FA token first
        const decryptedSecret = this.twoFaService.decryptSecret(user.twoFaSecret);
        const valid = this.twoFaService.verify2faToken(decryptedSecret, body.token);

        if (!valid) {
            this.logger.warn(`Failed 2FA verification for rotation attempt: ${user.id}`);
            throw new UnauthorizedException('Invalid 2FA token');
        }

        // Generate new secret
        const {secret, otpauthUrl} = this.twoFaService.rotate2faSecret(user.email);

        // Store new secret
        user.twoFaSecret = this.twoFaService.encryptSecret(secret);
        user.twoFaLastUsed = new Date();
        await this.authService.saveUser(user);

        this.logger.log(`2FA secret rotated successfully for user: ${user.id}`);
        return {
            message: '2FA secret rotated successfully',
            secret,
            otpauthUrl
        };
    }

    /**
     * Generates backup codes for a user's 2FA
     * Requires verification of the current 2FA token
     */
    @UseGuards(JwtAuthGuard)
    @Post('2fa/backup-codes/generate')
    @Throttle(twoFaThrottleOptions)
    @HttpCode(200)
    @ApiOperation({summary: 'Generate backup codes for 2FA'})
    @ApiBearerAuth()
    @ApiBody({type: TwoFactorAuthVerifyDto})
    @ApiOkResponse({
        description: 'Backup codes generated successfully',
        schema: {
            properties: {
                message: {type: 'string', example: 'Backup codes generated successfully'},
                backupCodes: {
                    type: 'array',
                    items: {type: 'string'},
                    example: ['ABCD-1234', 'EFGH-5678', 'IJKL-9012']
                }
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Unauthorized - invalid token or 2FA not enabled'})
    async generateBackupCodes(
        @Req() req: IAuthRequest,
        @Body() body: TwoFactorAuthVerifyDto,
    ) {
        const user = req.user;
        if (!user || typeof user.email !== 'string') {
            this.logger.warn(`Backup code generation attempt with invalid user`);
            throw new UnauthorizedException('User not found');
        }

        if (!user.twoFaSecret) {
            this.logger.warn(`Backup code generation attempt for user without 2FA enabled: ${user.id}`);
            throw new UnauthorizedException('2FA not enabled for this user');
        }

        // Verify current 2FA token first
        const decryptedSecret = this.twoFaService.decryptSecret(user.twoFaSecret);
        const valid = this.twoFaService.verify2faToken(decryptedSecret, body.token);

        if (!valid) {
            this.logger.warn(`Failed 2FA verification for backup code generation: ${user.id}`);
            throw new UnauthorizedException('Invalid 2FA token');
        }

        // Generate backup codes
        const {plainCodes, hashedCodes} = this.twoFaService.generateBackupCodes();

        // Store hashed backup codes
        user.twoFaBackupCodes = hashedCodes;
        await this.authService.saveUser(user);

        this.logger.log(`Backup codes generated for user: ${user.id}`);
        return {
            message: 'Backup codes generated successfully',
            backupCodes: plainCodes
        };
    }

    /**
     * Verifies a backup code for 2FA login
     */
    @Post('2fa/backup-codes/verify')
    @Throttle(twoFaThrottleOptions)
    @HttpCode(200)
    @ApiOperation({summary: 'Login with a 2FA backup code'})
    @ApiBody({type: TwoFactorAuthBackupDto})
    @ApiOkResponse({
        description: 'Backup code verification successful',
        schema: {
            properties: {
                email: {type: 'string', example: 'user@example.com'},
                id: {type: 'string', example: '123e4567-e89b-12d3-a456-426614174000'},
                token: {type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'},
                refreshToken: {type: 'string', example: '6fd8d272-375a-4d8f-b7a3-248db6c56b48'},
                message: {type: 'string', example: 'Login successful using backup code'},
                remainingCodes: {type: 'number', example: 9}
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Invalid backup code or no backup codes available'})
    async verifyBackupCode(@Body() body: TwoFactorAuthBackupDto) {
        const user = await this.authService.getUserByEmail(body.email);
        if (!user || !user.twoFaSecret || !user.twoFaBackupCodes || user.twoFaBackupCodes.length === 0) {
            this.logger.warn(`Backup code verification attempt for user without valid backup codes: ${body.email}`);
            throw new UnauthorizedException('No backup codes available for this user');
        }

        // Verify the backup code
        const codeIndex = this.twoFaService.verifyBackupCode(body.backupCode, user.twoFaBackupCodes);

        if (codeIndex === -1) {
            this.logger.warn(`Invalid backup code used for user: ${user.id}`);
            throw new UnauthorizedException('Invalid backup code');
        }

        // Remove the used backup code
        user.twoFaBackupCodes = user.twoFaBackupCodes.filter((_, index) => index !== codeIndex);
        user.twoFaLastUsed = new Date();
        await this.authService.saveUser(user);

        // Generate tokens
        const jwt = this.authService.generateJwt(user);
        const refreshToken = await this.authService.generateRefreshToken(user);

        this.logger.log(`Successful backup code verification for user: ${user.id}`);
        return {
            email: user.email,
            id: user.id,
            token: jwt,
            refreshToken,
            message: 'Login successful using backup code',
            remainingCodes: user.twoFaBackupCodes.length
        };
    }

    /**
     * Refreshes an access token using a valid refresh token.
     * Returns a new access token and refresh token pair.
     */
    @Post('refresh')
    @HttpCode(200)
    @Throttle({default: {limit: 10, ttl: 60000}})
    @ApiOperation({summary: 'Refresh access token using refresh token'})
    @ApiBody({type: RefreshTokenDto})
    @ApiOkResponse({
        description: 'Token refreshed successfully',
        schema: {
            properties: {
                token: {type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'},
                refreshToken: {type: 'string', example: '6fd8d272-375a-4d8f-b7a3-248db6c56b48'},
                message: {type: 'string', example: 'Token refreshed successfully'}
            }
        }
    })
    @ApiUnauthorizedResponse({description: 'Session expired, please login again'})
    @ApiForbiddenResponse({description: 'Session expired, please login again'})
    async refreshToken(@Body() body: RefreshTokenDto) {
        try {
            // Get the user ID from the database by validating the refresh token
            // The refreshJwtToken method will handle validation and token comparison
            const {token, refreshToken} = await this.authService.refreshJwtToken(
                body.userId,
                body.refreshToken
            );

            return {
                token,
                refreshToken,
                message: 'Token refreshed successfully',
            };
        } catch (error) {
            if (error.status === 403) {
                throw error; // Pass through ForbiddenException
            }
            this.logger.warn(`Failed token refresh attempt: ${error.message}`);
            throw new UnauthorizedException('Session expired, please login again');
        }
    }
}
