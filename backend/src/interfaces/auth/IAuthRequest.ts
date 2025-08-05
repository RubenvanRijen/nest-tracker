import { User } from '@backend/entities/user/user.entity';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import { IncomingHttpHeaders } from 'http';
import { Request } from 'express';

export interface IAuthRequest extends Request {
  user?: User;
  apiKey?: ApiKey;
  headers: IncomingHttpHeaders;
}
