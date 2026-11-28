import { randomBytes } from "node:crypto";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

let lastTime = 0;
let lastRandom = bytes(10);

/**
 * Monotonic ULID (26 Crockford base32 characters).
 * The timestamp prefix sorts by generation time; the random suffix increments
 * when two ids are minted in the same millisecond so a single process never
 * goes backwards.
 */
export function ulid(timestamp = Date.now()): string {
  let time = timestamp;
  let random: number[];
  if (time <= lastTime) {
    time = lastTime;
    random = increment(lastRandom);
  } else {
    random = [...randomBytes(10)];
  }
  lastTime = time;
  lastRandom = random;
  return encodeTime(time) + encodeRandom(random);
}

function encodeTime(time: number): string {
  let value = time;
  let encoded = "";
  for (let i = 0; i < 10; i += 1) {
    encoded = CROCKFORD[value % 32]! + encoded;
    value = Math.floor(value / 32);
  }
  return encoded;
}

function bytes(length: number): number[] {
  return Array.from({ length }, () => 0);
}

function encodeRandom(bytes: number[]): string {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let encoded = "";
  for (let i = 0; i < 16; i += 1) {
    encoded = CROCKFORD[Number(value & 31n)] + encoded;
    value >>= 5n;
  }
  return encoded;
}

function increment(values: number[]): number[] {
  const next = values.slice();
  for (let i = next.length - 1; i >= 0; i -= 1) {
    const value = (next[i] ?? 0) + 1;
    if (value <= 255) {
      next[i] = value;
      return next;
    }
    next[i] = 0;
  }
  return next;
}
