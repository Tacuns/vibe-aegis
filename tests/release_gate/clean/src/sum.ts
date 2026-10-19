import isNumber from 'is-number';
export const sum = (a: unknown, b: unknown) => (isNumber(a) && isNumber(b) ? Number(a) + Number(b) : 0);
