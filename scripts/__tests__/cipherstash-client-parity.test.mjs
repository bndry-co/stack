import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The EQL workspace and protect-ffi must resolve the same cipherstash-client.
 *
 * The SteVec selector pin
 * (`packages/eql/tests/encryption/tests/ste_vec_selectors.rs`) pins the
 * selectors cipherstash-client's `JsonIndexer` derives — the computation every
 * stored SteVec document depends on. It builds in the EQL workspace, against
 * the cipherstash-client `packages/eql/Cargo.lock` resolves. Customers'
 * documents are written by protect-ffi, a separate Cargo workspace with its own
 * lockfile. If the two resolve different versions, the pin passes against a
 * version customers do not run, and a protect-ffi-only bump reaches them with
 * the pin still green.
 *
 * Node builtins only: no cargo on `pnpm run test:scripts` (see AGENTS.md).
 */

const EQL_LOCK = 'packages/eql/Cargo.lock'
const FFI_LOCK = 'languages/typescript/packages/protect-ffi/Cargo.lock'

/** Every version of `name` a `Cargo.lock` records, sorted. */
export function lockedVersions(source, name) {
  return source
    .split(/^\[\[package\]\]$/m)
    .slice(1)
    .filter((block) => new RegExp(`^name = "${name}"$`, 'm').test(block))
    .map((block) => /^version = "([^"]*)"$/m.exec(block)?.[1])
    .filter(Boolean)
    .sort()
}

const read = (file) => readFileSync(join(REPO_ROOT, file), 'utf8')

describe('cipherstash-client parity between the EQL workspace and protect-ffi', () => {
  const eql = lockedVersions(read(EQL_LOCK), 'cipherstash-client')
  const ffi = lockedVersions(read(FFI_LOCK), 'cipherstash-client')

  it('finds exactly one cipherstash-client in each lock', () => {
    // The floor: a rename or a lock that stops naming the crate would make
    // the comparison below vacuous.
    expect(eql).toHaveLength(1)
    expect(ffi).toHaveLength(1)
  })

  it('resolves the same cipherstash-client version in both locks', () => {
    expect(
      eql,
      `${EQL_LOCK} resolves cipherstash-client ${eql}, ${FFI_LOCK} resolves ${ffi}: ` +
        'the SteVec selector pin tests a version protect-ffi does not ship. ' +
        'Move the EQL workspace pins (tests/encryption, tests/sqlx) to match.',
    ).toEqual(ffi)
  })
})
