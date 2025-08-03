import { User } from '@backend/entities/user/user.entity';

export interface IAuthRequest extends Request {
  user: User;
}
