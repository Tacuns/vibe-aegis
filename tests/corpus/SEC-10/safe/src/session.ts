import jwt from 'jsonwebtoken';
export function user(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET!);
}
