import jwt from 'jsonwebtoken';
export function user(token: string) {
  return jwt.decode(token);
}
