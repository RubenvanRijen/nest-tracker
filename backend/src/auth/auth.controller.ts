import {
  Controller,
  Post,
  Body,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  async register(@Body() body: RegisterDto) {
    try {
      const user = await this.authService.registerUser(
        body.email,
        body.password,
      );
      return {
        email: user.email,
        id: user.id,
        message: 'Registration successful',
      };
    } catch (err: unknown) {
      return { error: err instanceof Error ? err.message : 'Unknown error' };
    }
  }

  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    const user = await this.authService.getUserByEmail(body.email);
    if (!user) {
      return { error: 'Invalid credentials' };
    }
    const valid = await this.authService.comparePassword(
      body.password,
      user.passwordHash,
    );
    if (!valid) {
      return { error: 'Invalid credentials' };
    }
    // TODO: Issue JWT token here
    return { email: user.email, id: user.id, message: 'Login successful' };
  }
}
