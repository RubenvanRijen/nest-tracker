import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../src/entities/user/user.entity';
import { Repository } from 'typeorm';
import { AuthService } from '../src/services/auth/auth.service';

describe('Authentication (e2e)', () => {
  let app: INestApplication;
  let userRepository: Repository<User>;
  let authService: AuthService;
  let testUser: User;
  let jwtToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();

    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
    authService = moduleFixture.get<AuthService>(AuthService);

    // Clean up any existing test users
    await userRepository.delete({ email: 'test@example.com' });
  });

  afterAll(async () => {
    // Clean up test data
    if (testUser) {
      await userRepository.delete(testUser.id);
    }
    await app.close();
  });

  describe('Registration', () => {
    it('should register a new user', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssword123',
        })
        .expect(201)
        .expect(res => {
          expect(res.body).toHaveProperty('email', 'test@example.com');
          expect(res.body).toHaveProperty('id');
          expect(res.body).toHaveProperty('message', 'Registration successful');
        });
    });

    it('should reject registration with existing email', async () => {
      // First, ensure our test user exists
      const existingUser = await userRepository.findOne({ where: { email: 'test@example.com' } });
      testUser = existingUser; // Save for later tests

      return request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssword123',
        })
        .expect(400)
        .expect(res => {
          expect(res.body.message).toContain('already exists');
        });
    });

    it('should reject registration with weak password', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'newuser@example.com',
          password: 'password', // Common password
        })
        .expect(400);
    });
  });

  describe('Login', () => {
    it('should login with valid credentials', () => {
      return request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssword123',
        })
        .expect(201)
        .expect(res => {
          expect(res.body).toHaveProperty('token');
          expect(res.body).toHaveProperty('refreshToken');
          expect(res.body).toHaveProperty('message', 'Login successful');
          jwtToken = res.body.token; // Save for later tests
        });
    });

    it('should reject login with invalid credentials', () => {
      return request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'WrongPassword123!',
        })
        .expect(401)
        .expect(res => {
          expect(res.body.message).toBe('Authentication failed');
        });
    });
  });

  describe('Protected Routes', () => {
    it('should access protected route with valid JWT', async () => {
      // This assumes you have a protected route to test
      // For example, the 2FA status endpoint
      return request(app.getHttpServer())
        .get('/auth/2fa/status')
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(200)
        .expect(res => {
          expect(res.body).toHaveProperty('enabled');
        });
    });

    it('should reject access to protected route without JWT', () => {
      return request(app.getHttpServer())
        .get('/auth/2fa/status')
        .expect(401);
    });
  });

  describe('2FA Setup', () => {
    it('should initiate 2FA setup', () => {
      return request(app.getHttpServer())
        .post('/auth/2fa/setup')
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(201)
        .expect(res => {
          expect(res.body).toHaveProperty('secret');
          expect(res.body).toHaveProperty('otpauthUrl');
        });
    });
  });

  // Note: Full 2FA testing would require generating valid TOTP tokens
  // which is challenging in an automated test. Consider mocking the verification.
});