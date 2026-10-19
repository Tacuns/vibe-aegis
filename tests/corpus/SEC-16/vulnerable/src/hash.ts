import crypto from 'crypto';
export const hashPassword = (p: string) => crypto.createHash('md5').update(p).digest('hex');
