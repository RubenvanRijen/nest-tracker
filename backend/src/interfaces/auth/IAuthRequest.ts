import { User } from '@backend/entities/user/user.entity';
import { IncomingHttpHeaders } from 'http';
import { Request } from 'express';

export interface IAuthRequest extends Request {
  user?: User;
  headers: IncomingHttpHeaders;
}
