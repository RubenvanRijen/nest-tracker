import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import supertest, { Response } from 'supertest';
import { AppModule } from '../src/app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../src/entities/user/user.entity';
import { Repository } from 'typeorm';
import { Server } from 'http';

// Define response types for better type safety
interface AuthResponse {
  email?: string;
  id?: string;
  message?: string;
  token?: string;
  refreshToken?: string;
  enabled?: boolean;
  secret?: string;
  otpauthUrl?: string;
}

describe('Authentication (e2e)', () => {
  let app: INestApplication;
  let userRepository: Repository<User>;
  let testUser: User;
  let jwtToken: string;
  let api: supertest.SuperTest<supertest.Test>;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();

    // Initialize the typed supertest instance
    // Using type assertion to safely type the HTTP server
    const httpServer = app.getHttpServer() as Server;
    api = supertest(httpServer);

    userRepository = moduleFixture.get<Repository<User>>(
      getRepositoryToken(User),
    );

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
      return api
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssword123',
        })
        .expect(201)
        .expect((res: Response) => {
          const body = res.body as AuthResponse;
          expect(body).toHaveProperty('email', 'test@example.com');
          expect(body).toHaveProperty('id');
          expect(body).toHaveProperty('message', 'Registration successful');
        });
    });

    it('should reject registration with existing email', async () => {
      // First, ensure our test user exists
      const foundUser = await userRepository.findOne({
        where: { email: 'test@example.com' },
      }); // Save for later tests

      if (!foundUser) {
        fail(
          'Test user not found in the database. Registration test may have failed.',
        );
      }

      testUser = foundUser;

      return api
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssword123',
        })
        .expect(400)
        .expect((res: Response) => {
          const body = res.body as AuthResponse;
          expect(body.message).toContain('already exists');
        });
    });

    it('should reject registration with weak password', () => {
      return api
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
      return api
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssword123',
        })
        .expect(201)
        .expect((res: Response) => {
          const body = res.body as AuthResponse;
          expect(body).toHaveProperty('token');
          expect(body).toHaveProperty('refreshToken');
          expect(body).toHaveProperty('message', 'Login successful');
          jwtToken = body.token as string; // Save for later tests
        });
    });

    it('should reject login with invalid credentials', () => {
      return api
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'WrongPassword123!',
        })
        .expect(401)
        .expect((res: Response) => {
          const body = res.body as AuthResponse;
          expect(body.message).toBe('Authentication failed');
        });
    });
  });

  describe('Protected Routes', () => {
    it('should access protected route with valid JWT', async () => {
      // This assumes you have a protected route to test
      // For example, the 2FA status endpoint
      await api
        .get('/auth/2fa/status')
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(200)
        .expect((res: Response) => {
          const body = res.body as AuthResponse;
          expect(body).toHaveProperty('enabled');
        });
    });

    it('should reject access to protected route without JWT', () => {
      return api.get('/auth/2fa/status').expect(401);
    });
  });

  describe('2FA Setup', () => {
    it('should initiate 2FA setup', () => {
      return api
        .post('/auth/2fa/setup')
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(201)
        .expect((res: Response) => {
          const body = res.body as AuthResponse;
          expect(body).toHaveProperty('secret');
          expect(body).toHaveProperty('otpauthUrl');
        });
    });
  });

  // Note: Full 2FA testing would require generating valid TOTP tokens
  // which is challenging in an automated test. Consider mocking the verification.
});
