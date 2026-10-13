/**
 * Pins how `stash decrypt` pairs an encrypted column with its plaintext twin.
 *
 * The pairing is what every later step trusts: the backfill fills that column,
 * and `decrypt drop`'s coverage gate verifies it before destroying the
 * ciphertext. A pairing that silently drifted — a flag naming a different
 * column mid-lifecycle — would let that gate pass against the wrong column.
 */

import type {
  EncryptedColumnInfo,
  MigrationStateRow,
} from '@cipherstash/migrate'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Only the catalog/state probes are replaced; the domain mapping and phase
// predicates stay real so a rename on either side fails loudly.
const probes = vi.hoisted(() => ({
  listEncryptedColumns: vi.fn(async (): Promise<EncryptedColumnInfo[]> => []),
  columnExists: vi.fn(async () => true),
  detectColumnEqlVersion: vi.fn(async (): Promise<2 | 3 | null> => null),
  columnSqlType: vi.fn(async (): Promise<string | null> => null),
  progress: vi.fn(async (): Promise<Partial<MigrationStateRow> | null> => null),
  readManifest: vi.fn(async (): Promise<unknown> => null),
}))
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  ...probes,
}))
vi.mock('@/commands/encrypt/context.js', () => ({
  loadEncryptionContext: vi.fn(),
  requireTable: vi.fn(),
}))

import type pg from 'pg'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'
import { resolveDecryptPair } from '../lib/resolve-pair.js'

const db = {} as pg.ClientBase
const EMAIL_ENC: EncryptedColumnInfo = {
  column: 'email_encrypted',
  domain: 'eql_v3_text_search',
  version: 3,
}

function reverseState(plaintextColumn: string): Partial<MigrationStateRow> {
  return {
    event: 'decrypt_checkpoint',
    phase: 'decrypting',
    details: { plaintextColumn },
  }
}

async function failure(promise: Promise<unknown>): Promise<Error> {
  const error = await promise.catch((e: unknown) => e)
  expect(error).toBeInstanceOf(BackfillConfigError)
  return error as Error
}

describe('resolveDecryptPair', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    probes.listEncryptedColumns.mockResolvedValue([EMAIL_ENC])
    probes.detectColumnEqlVersion.mockResolvedValue(null)
    probes.columnSqlType.mockResolvedValue(null)
    probes.progress.mockResolvedValue(null)
    probes.readManifest.mockResolvedValue(null)
  })

  it('maps the domain back to its plaintext type', async () => {
    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.domain).toBe('eql_v3_text_search')
    expect(pair.mapping?.sqlType).toBe('text')
  })

  it('prefers the original name the forward manifest recorded', async () => {
    probes.readManifest.mockResolvedValue({
      version: 1,
      tables: {
        users: [
          { column: 'email_address', encryptedColumn: 'email_encrypted' },
        ],
      },
    })

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair).toMatchObject({
      plaintextColumn: 'email_address',
      via: 'manifest',
    })
  })

  it('falls back to the _encrypted convention, then to <name>_plaintext', async () => {
    const conventional = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(conventional).toMatchObject({
      plaintextColumn: 'email',
      via: 'convention',
    })

    probes.listEncryptedColumns.mockResolvedValue([
      { column: 'secret', domain: 'eql_v3_text', version: 3 },
    ])
    const fallback = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'secret',
    })
    expect(fallback).toMatchObject({
      plaintextColumn: 'secret_plaintext',
      via: 'fallback',
    })
  })

  it('reuses the pairing an earlier reverse run recorded', async () => {
    probes.progress.mockResolvedValue(reverseState('contact_email'))

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair).toMatchObject({
      plaintextColumn: 'contact_email',
      via: 'recorded',
    })
  })

  it('refuses a --plaintext-column that contradicts the recorded pairing', async () => {
    probes.progress.mockResolvedValue(reverseState('contact_email'))

    const error = await failure(
      resolveDecryptPair(db, {
        table: 'users',
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'email',
      }),
    )
    expect(error.message).toContain(
      'already being reversed into "contact_email"',
    )
    expect(error.message).toContain('coverage check')
  })

  it('ignores forward history under the same key — only reverse events pair', async () => {
    probes.progress.mockResolvedValue({
      event: 'backfilled',
      phase: 'backfilled',
      details: { plaintextColumn: 'not-a-reverse-record' },
    })

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.state).toBeNull()
    expect(pair.via).toBe('convention')
  })

  it('names a missing source column, listing the EQL columns that do exist', async () => {
    probes.columnExists.mockResolvedValue(false)

    const error = await failure(
      resolveDecryptPair(db, { table: 'users', encryptedColumn: 'email' }),
    )
    expect(error.message).toContain('Column email does not exist on users')
    expect(error.message).toContain('email_encrypted')
  })

  it('refuses a source that is plaintext already', async () => {
    probes.columnExists.mockResolvedValue(true)

    const error = await failure(
      resolveDecryptPair(db, { table: 'users', encryptedColumn: 'email' }),
    )
    expect(error.message).toContain('is not an EQL v3 column')
  })

  it('refuses a target that is itself encrypted', async () => {
    probes.detectColumnEqlVersion.mockResolvedValue(3)

    const error = await failure(
      resolveDecryptPair(db, {
        table: 'users',
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'other_encrypted',
      }),
    )
    expect(error.message).toContain('is itself an EQL v3 column')
  })

  it('reports the twin’s declared type once it exists', async () => {
    probes.columnSqlType.mockResolvedValue('character varying(255)')

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.plaintextSqlType).toBe('character varying(255)')
  })
})
