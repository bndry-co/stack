/**
 * `stash decrypt backfill` — the command shell around `runDecryptBackfill`.
 * The engine itself is covered against real Postgres in
 * `@cipherstash/migrate`'s `decrypt.integration.test.ts`; this pins what the
 * command adds: the twin-must-exist guard, the reverse dual-write gate, the
 * undecryptable-row report, and which errors are allowed to print verbatim.
 */

import {
  type DecryptBackfillResult,
  ForcedPassIncompleteError,
  PlaintextWriteError,
  UndecryptableBatchError,
} from '@cipherstash/migrate'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DecryptPair, TwinHazard } from '../lib/resolve-pair.js'

const releaseMock = vi.hoisted(() => vi.fn())
vi.mock('pg', () => ({
  default: {
    Pool: class {
      connect = vi.fn(async () => ({ release: releaseMock, query: vi.fn() }))
      end = vi.fn(async () => {})
    },
  },
}))

const migrateMocks = vi.hoisted(() => ({
  installMigrationsSchema: vi.fn(async () => {}),
  appendEvent: vi.fn(async () => {}),
  runDecryptBackfill: vi.fn(
    async (): Promise<DecryptBackfillResult> => ({
      resumed: false,
      rowsProcessed: 10,
      rowsTotal: 10,
      rowsDecrypted: 10,
      rowsSkipped: 0,
      skippedByCode: {},
      nullPlaintextPks: [],
      completed: true,
    }),
  ),
}))
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  ...migrateMocks,
}))

const resolveMock = vi.hoisted(() => vi.fn())
const hazardMock = vi.hoisted(() =>
  vi.fn(async (): Promise<TwinHazard | null> => null),
)
vi.mock('../lib/resolve-pair.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/resolve-pair.js')>()),
  resolveDecryptPair: resolveMock,
  assessExistingTwin: hazardMock,
}))

const decryptionClient = vi.hoisted(() => ({ bulkDecrypt: vi.fn() }))
vi.mock('@/commands/encrypt/context.js', () => ({
  loadEncryptionContext: vi.fn(async () => ({
    client: decryptionClient,
    tables: new Map(),
  })),
  requireTable: vi.fn(),
}))
vi.mock('@/commands/encrypt/lib/db-readers.js', () => ({
  detectPkColumn: vi.fn(async () => 'id'),
}))
vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: {
    info: vi.fn(),
    success: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    step: vi.fn(),
  },
}))
vi.mock('@/config/index.js', () => ({
  loadStashConfig: vi.fn(async () => ({ databaseUrl: 'postgres://test' })),
}))
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: vi.fn(() => 'npm'),
  runnerCommand: vi.fn((_pm: string, ref: string) => `npx ${ref}`),
}))

import * as p from '@clack/prompts'
import { decryptBackfillCommand } from '../backfill.js'

function pair(overrides: Partial<DecryptPair> = {}): DecryptPair {
  return {
    table: 'users',
    encryptedColumn: 'email_encrypted',
    domain: 'eql_v3_text_search',
    mapping: { domain: 'eql_v3_text_search', family: 'text', sqlType: 'text' },
    plaintextColumn: 'email',
    via: 'convention',
    plaintextSqlType: 'text',
    state: null,
    // A recorded reverse event means a lifecycle in progress, unless a test
    // says otherwise.
    lifecycleActive: overrides.state !== undefined && overrides.state !== null,
    forwardState: null,
    ...overrides,
  }
}

const reverseInFlight = {
  id: '1',
  tableName: 'users',
  columnName: 'email_encrypted',
  event: 'decrypt_checkpoint' as const,
  phase: 'decrypting' as const,
  cursorValue: '5',
  rowsProcessed: 5,
  rowsTotal: 10,
  details: { plaintextColumn: 'email' },
  createdAt: new Date(0),
}

function spyExit() {
  return vi
    .spyOn(process, 'exit')
    .mockImplementation((() => undefined) as never)
}

describe('decrypt backfill', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resolveMock.mockResolvedValue(pair({ state: reverseInFlight }))
    hazardMock.mockResolvedValue(null)
    vi.mocked(p.confirm).mockResolvedValue(true)
  })

  it('decrypts into the twin with its declared type, 500 rows per ZeroKMS request by default', async () => {
    resolveMock.mockResolvedValue(
      pair({
        state: reverseInFlight,
        plaintextSqlType: 'character varying(64)',
      }),
    )

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    expect(migrateMocks.runDecryptBackfill).toHaveBeenCalledWith(
      expect.objectContaining({
        decryptionClient,
        tableName: 'users',
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'email',
        plaintextSqlType: 'character varying(64)',
        pkColumn: 'id',
        chunkSize: 500,
      }),
    )
  })

  it('refuses to start before the plaintext twin exists, pointing at decrypt plan', async () => {
    resolveMock.mockResolvedValue(pair({ plaintextSqlType: null }))
    const exitSpy = spyExit()

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining(
        'stash decrypt plan --table users --column email_encrypted',
      ),
    )
    expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('non-interactive first run: refuses without --confirm-dual-writes-deployed', async () => {
    resolveMock.mockResolvedValue(pair({ state: null }))

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('--confirm-dual-writes-deployed'),
    )
    expect(migrateMocks.appendEvent).not.toHaveBeenCalled()
    expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
  })

  it('records the reverse dual-write gate, with the pairing, on first acceptance', async () => {
    resolveMock.mockResolvedValue(pair({ state: null }))

    await decryptBackfillCommand({
      table: 'users',
      column: 'email_encrypted',
      confirmDualWritesDeployed: true,
    })

    expect(migrateMocks.appendEvent).toHaveBeenCalledWith(expect.anything(), {
      tableName: 'users',
      columnName: 'email_encrypted',
      event: 'decrypt_dual_writing',
      phase: 'decrypt-dual-writing',
      details: { plaintextColumn: 'email' },
    })
    expect(migrateMocks.runDecryptBackfill).toHaveBeenCalled()
  })

  it('reports undecryptable rows as a lock-context limitation, with codes and the drop consequence', async () => {
    migrateMocks.runDecryptBackfill.mockResolvedValueOnce({
      resumed: false,
      rowsProcessed: 10,
      rowsTotal: 10,
      rowsDecrypted: 7,
      rowsSkipped: 3,
      skippedByCode: { UNKNOWN: 3 },
      nullPlaintextPks: [],
      completed: true,
    })

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    const warning = vi
      .mocked(p.log.warn)
      .mock.calls.map(([message]) => message)
      .find((message) => message.includes('could not be decrypted'))
    expect(warning).toContain('3 row(s) of users.email_encrypted')
    expect(warning).toContain('3 × UNKNOWN')
    expect(warning).toContain('lock context')
    expect(warning).toContain('`stash decrypt drop` refuses')
    expect(p.outro).toHaveBeenCalledWith(
      'Decrypt backfill complete. 7 rows decrypted, 3 skipped.',
    )
  })

  it('prints an UndecryptableBatchError verbatim — it carries counts and codes only', async () => {
    migrateMocks.runDecryptBackfill.mockRejectedValueOnce(
      new UndecryptableBatchError(500, { UNKNOWN: 500 }),
    )
    const exitSpy = spyExit()

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('None of the 500 row(s) in the first batch'),
    )
    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('--continue-on-undecryptable'),
    )
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('suppresses the text of any other error', async () => {
    migrateMocks.runDecryptBackfill.mockRejectedValueOnce(
      new Error('upstream said: alice@example.com'),
    )
    const exitSpy = spyExit()

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    const messages = vi.mocked(p.log.error).mock.calls.map(([m]) => m)
    expect(messages.join('\n')).not.toContain('alice@example.com')
    expect(messages).toContain(
      'Decrypt backfill failed (Error). Re-run with diagnostic logging if you need details.',
    )
    exitSpy.mockRestore()
  })

  it('rejects a chunk size that is not a positive whole number', async () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((
      code?: number,
    ) => {
      throw new Error(`exit ${code}`)
    }) as never)

    await expect(
      decryptBackfillCommand({
        table: 'users',
        column: 'email_encrypted',
        chunkSize: Number('abc'),
      }),
    ).rejects.toThrow('exit 1')
    expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
    exitSpy.mockRestore()
  })

  it('rejects a chunk size above what one write can bind', async () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((
      code?: number,
    ) => {
      throw new Error(`exit ${code}`)
    }) as never)

    await expect(
      decryptBackfillCommand({
        table: 'users',
        column: 'email_encrypted',
        chunkSize: 32768,
      }),
    ).rejects.toThrow('exit 1')
    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('from 1 to 32767'),
    )
    expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
    exitSpy.mockRestore()
  })

  describe('a plaintext twin that already holds values (first run)', () => {
    const prepopulated: TwinHazard = { kind: 'prepopulated' }
    const forwardSource: TwinHazard = {
      kind: 'forward-source',
      forwardPhase: 'backfilled',
      hasValues: true,
    }

    beforeEach(() => {
      resolveMock.mockResolvedValue(pair({ state: null }))
    })

    it('refuses it, recording nothing and decrypting nothing', async () => {
      hazardMock.mockResolvedValue(prepopulated)
      const exitSpy = spyExit()

      await decryptBackfillCommand({
        table: 'users',
        column: 'email_encrypted',
        confirmDualWritesDeployed: true,
      })

      const message = vi.mocked(p.log.error).mock.calls[0]?.[0] ?? ''
      expect(message).toContain('users.email already holds values')
      expect(message).toContain('--force')
      expect(message).toContain('--confirm-plaintext-current')
      expect(migrateMocks.appendEvent).not.toHaveBeenCalled()
      expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
      expect(exitSpy).toHaveBeenCalledWith(1)
      exitSpy.mockRestore()
    })

    it('refuses the source column of a forward encryption that was never dropped', async () => {
      hazardMock.mockResolvedValue(forwardSource)
      const exitSpy = spyExit()

      await decryptBackfillCommand({
        table: 'users',
        column: 'email_encrypted',
        confirmDualWritesDeployed: true,
      })

      const message = vi.mocked(p.log.error).mock.calls[0]?.[0] ?? ''
      expect(message).toContain(
        "forward phase 'backfilled' in cipherstash.cs_migrations",
      )
      expect(message).toContain('the only current copy')
      expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
      exitSpy.mockRestore()
    })

    it('--force overwrites it from the ciphertext, and the gate records the choice', async () => {
      hazardMock.mockResolvedValue(forwardSource)

      await decryptBackfillCommand({
        table: 'users',
        column: 'email_encrypted',
        confirmDualWritesDeployed: true,
        force: true,
      })

      expect(migrateMocks.appendEvent).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          event: 'decrypt_dual_writing',
          details: {
            plaintextColumn: 'email',
            existingPlaintext: 'forward-source',
            acknowledgedWith: 'force',
          },
        }),
      )
      expect(migrateMocks.runDecryptBackfill).toHaveBeenCalledWith(
        expect.objectContaining({ force: true }),
      )
    })

    it('--confirm-plaintext-current keeps it and fills only the NULLs', async () => {
      hazardMock.mockResolvedValue(prepopulated)

      await decryptBackfillCommand({
        table: 'users',
        column: 'email_encrypted',
        confirmDualWritesDeployed: true,
        confirmPlaintextCurrent: true,
      })

      expect(p.log.warn).toHaveBeenCalledWith(
        expect.stringContaining('Proceeding under --confirm-plaintext-current'),
      )
      expect(migrateMocks.appendEvent).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          details: expect.objectContaining({
            existingPlaintext: 'prepopulated',
            acknowledgedWith: 'confirm-plaintext-current',
          }),
        }),
      )
      expect(migrateMocks.runDecryptBackfill).toHaveBeenCalledWith(
        expect.not.objectContaining({ force: true }),
      )
    })

    it('checks the twin before the --force prompt, so cancelling it records nothing', async () => {
      hazardMock.mockResolvedValue(prepopulated)
      vi.mocked(p.confirm).mockResolvedValueOnce(false)

      await decryptBackfillCommand({
        table: 'users',
        column: 'email_encrypted',
        confirmDualWritesDeployed: true,
        force: true,
      })

      // Had the gate's event been recorded first, the next run would treat
      // the twin's values as this lifecycle's own and skip the check.
      expect(hazardMock).toHaveBeenCalled()
      expect(migrateMocks.appendEvent).not.toHaveBeenCalled()
      expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
    })
  })

  it('a finished earlier lifecycle does not pass the dual-write gate', async () => {
    resolveMock.mockResolvedValue(
      pair({
        state: {
          ...reverseInFlight,
          event: 'encrypted_dropped',
          phase: 'encrypted-dropped',
        },
        lifecycleActive: false,
      }),
    )

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('--confirm-dual-writes-deployed'),
    )
    expect(migrateMocks.runDecryptBackfill).not.toHaveBeenCalled()
  })

  it('--force says it is safe only while dual-writes are live', async () => {
    await decryptBackfillCommand({
      table: 'users',
      column: 'email_encrypted',
      force: true,
    })

    expect(p.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('Safe only while dual-writes are live'),
    )
    const warnings = vi.mocked(p.log.warn).mock.calls.map(([m]) => m)
    expect(warnings.join('\n')).not.toContain('not destructive')
  })

  it('tells the application to keep writing both columns until the drop is applied', async () => {
    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    const steps = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) =>
        String(title).startsWith('Next steps'),
      )?.[0]
    expect(steps).toContain(
      'Keep writing BOTH email_encrypted and email on every insert and update until the drop migration is applied',
    )
    expect(steps).not.toMatch(/stop writing email_encrypted once reads/)
  })

  it('prints a PlaintextWriteError verbatim — it carries names and a SQLSTATE only', async () => {
    migrateMocks.runDecryptBackfill.mockRejectedValueOnce(
      new PlaintextWriteError('22P02', 'email', 'integer', undefined),
    )
    const exitSpy = spyExit()

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('"email" (integer): SQLSTATE 22P02'),
    )
    exitSpy.mockRestore()
  })

  it('prints a ForcedPassIncompleteError verbatim — finishing a --force pass needs --force', async () => {
    migrateMocks.runDecryptBackfill.mockRejectedValueOnce(
      new ForcedPassIncompleteError('users', 'email_encrypted'),
    )
    const exitSpy = spyExit()

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('Re-run with --force to finish it'),
    )
    exitSpy.mockRestore()
  })

  it('reports rows that decrypt to null apart from lock-context failures, with their keys', async () => {
    migrateMocks.runDecryptBackfill.mockResolvedValueOnce({
      resumed: false,
      rowsProcessed: 10,
      rowsTotal: 10,
      rowsDecrypted: 7,
      rowsSkipped: 3,
      skippedByCode: { UNKNOWN: 1, NULL_PLAINTEXT: 2 },
      nullPlaintextPks: ['4', '9'],
      completed: true,
    })

    await decryptBackfillCommand({ table: 'users', column: 'email_encrypted' })

    const warning =
      vi
        .mocked(p.log.warn)
        .mock.calls.map(([message]) => message)
        .find((message) => message.includes('could not be decrypted')) ?? ''
    const [lockBound, nulls] = warning.split('\n\n')
    expect(lockBound).toContain('1 row(s) of users.email_encrypted')
    expect(lockBound).toContain('1 × UNKNOWN')
    expect(lockBound).not.toContain('NULL_PLAINTEXT')
    expect(nulls).toContain('2 row(s) of users.email_encrypted')
    expect(nulls).toContain('decrypts to an empty (null) value')
    expect(nulls).toContain('not a credentials or lock-context problem')
    expect(nulls).toContain('Primary keys: 4, 9')
  })
})
