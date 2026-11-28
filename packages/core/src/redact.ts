const SECRET_KEY = /secret|password|passwd|token|api[-_]?key|authorization|credential|cookie|session/i;
const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const BEARER = /Bearer\s+\S+/gi;
const SK_KEY = /\bsk-[A-Za-z0-9]{8,}\b/g;

/**
 * Mask secrets and a few obvious PII shapes before they are written to the
 * audit log. This is not the heuristic scanner (milestone 3). The raw value
 * is still hashed separately so an auditor can correlate a call without
 * storing the secret.
 */
export function redact(value: unknown): unknown {
  return redactValue(value);
}

function redactValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (value !== null && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (SECRET_KEY.test(key) && (typeof child === "string" || typeof child === "number" || typeof child === "boolean")) {
        output[key] = "[REDACTED]";
      } else {
        output[key] = redactValue(child);
      }
    }
    return output;
  }
  if (typeof value === "string") return redactString(value);
  return value;
}

/**
 * Keep the domain visible and mask the local part as its first character
 * plus three bullets. `john@outsidecorp.com` becomes `j•••@outsidecorp.com`.
 * A one-character local part works the same way: `q@outside-sample.example`
 * becomes `q•••@outside-sample.example`.
 */
export function maskEmail(address: string): string {
  const at = address.lastIndexOf("@");
  if (at <= 0 || at === address.length - 1) return address;
  return `${address[0]}•••@${address.slice(at + 1)}`;
}

function redactString(value: string): string {
  return value
    .replace(EMAIL, (address) => maskEmail(address))
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(SK_KEY, "[REDACTED]");
}
