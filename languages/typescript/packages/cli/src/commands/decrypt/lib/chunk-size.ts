import { MAX_DECRYPT_CHUNK_SIZE } from '@cipherstash/migrate'

/**
 * `decrypt backfill --chunk-size` validation.
 *
 * `Number(...)` accepts `1e3`, `0x10` and `Infinity`, and has no ceiling. The
 * ceiling matters here: each decrypted row binds two parameters in the
 * chunk's write, and Postgres caps a statement at 65535 parameters, so a
 * chunk above {@link MAX_DECRYPT_CHUNK_SIZE} rows would fail at the write,
 * after its ZeroKMS request had already been made.
 *
 * The shape rule (plain decimal digits, a positive safe integer) is the one
 * `encrypt backfill` adopts in #1194 (`parseChunkSize` in
 * `src/cli/chunk-size.ts`). When that lands, this function should delegate
 * the shape check to it and keep only the maximum.
 */

/**
 * Thrown for a chunk size that is not a whole number from 1 to
 * {@link MAX_DECRYPT_CHUNK_SIZE}. The message names the flag and quotes what
 * was received; it carries no row data, so it prints verbatim.
 */
export class InvalidDecryptChunkSizeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidDecryptChunkSizeError'
  }
}

/**
 * Parse a `--chunk-size` value: the flag's raw argv text (so the error can
 * quote it) or an already-coerced number (what a handler receives).
 */
export function parseDecryptChunkSize(input: string | number): number {
  const value =
    typeof input === 'string'
      ? /^\s*\d+\s*$/.test(input)
        ? Number(input)
        : Number.NaN
      : input

  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_DECRYPT_CHUNK_SIZE
  ) {
    const received =
      typeof input === 'string' ? JSON.stringify(input) : String(input)
    throw new InvalidDecryptChunkSizeError(
      `--chunk-size must be a whole number of rows from 1 to ${MAX_DECRYPT_CHUNK_SIZE} (got ${received}). Each row binds two parameters in the write, and Postgres allows 65535 per statement.`,
    )
  }
  return value
}
