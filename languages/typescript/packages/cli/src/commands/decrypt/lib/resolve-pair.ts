import {
  columnExists,
  columnHasValues,
  columnSqlType,
  detectColumnEqlVersion,
  isReverseMigrationPhase,
  listEncryptedColumns,
  type MigrationPhase,
  type MigrationStateRow,
  type PlaintextTypeMapping,
  plaintextTypeForEqlDomain,
  progress,
  readManifest,
} from '@cipherstash/migrate'
import type pg from 'pg'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'

/**
 * How the plaintext twin's name was decided. Destructive steps trust only the
 * first two: `flag` is the user saying so, `recorded` is the pairing the
 * reverse backfill actually ran against. The rest are proposals.
 */
export type PlaintextResolution =
  | 'flag'
  | 'recorded'
  | 'manifest'
  | 'convention'
  | 'fallback'

/** One encrypted column and the plaintext twin it reverses into. */
export interface DecryptPair {
  table: string
  /** The EQL v3 column being reversed — the source. */
  encryptedColumn: string
  /** Its unqualified domain, e.g. `eql_v3_text_search`. */
  domain: string
  /**
   * The plaintext type the domain maps back to, or `null` for a domain this
   * release cannot map (a SteVec fragment, or a domain newer than the CLI).
   */
  mapping: PlaintextTypeMapping | null
  /** The plaintext twin — the target. */
  plaintextColumn: string
  via: PlaintextResolution
  /**
   * The twin's declared type (`format_type`) when it already exists, else
   * `null`. Present means `stash decrypt plan` has nothing left to add.
   */
  plaintextSqlType: string | null
  /**
   * Latest REVERSE event for this encrypted column, if any. It can belong to
   * an earlier, finished lifecycle; {@link lifecycleActive} says whether it
   * is the one in progress.
   */
  state: MigrationStateRow | null
  /** Whether {@link state} belongs to the reverse lifecycle in progress. */
  lifecycleActive: boolean
  /**
   * Latest FORWARD event recorded under the plaintext twin's name: the
   * forward lifecycle that encrypted it, when there was one. Forward events
   * are keyed by the plaintext column, so this is where they live.
   */
  forwardState: MigrationStateRow | null
}

/**
 * The reverse lifecycle's state for one encrypted column: its latest event,
 * but only when that event belongs to the reverse lifecycle. Reverse events
 * are keyed by the encrypted column precisely so forward history never shows
 * up here, but a hand-written or legacy row under the same key must not be
 * mistaken for reverse progress either.
 */
export async function reverseState(
  client: pg.ClientBase,
  table: string,
  encryptedColumn: string,
): Promise<MigrationStateRow | null> {
  const last = await progress(client, table, encryptedColumn).catch(
    (error: unknown) => {
      // `cs_migrations` not installed yet: no reverse history, which is a
      // normal state for `plan`/`status` on a fresh project.
      if (
        error instanceof Error &&
        /cs_migrations|schema "cipherstash"/i.test(error.message)
      ) {
        return null
      }
      throw error
    },
  )
  return last && isReverseMigrationPhase(last.phase) ? last : null
}

/**
 * The forward lifecycle's state for a plaintext column: its latest event, but
 * only when that event is a forward one. `null` when there is no history or
 * no `cs_migrations` table yet.
 */
export async function forwardState(
  client: pg.ClientBase,
  table: string,
  plaintextColumn: string,
): Promise<MigrationStateRow | null> {
  const last = await progress(client, table, plaintextColumn).catch(
    (error: unknown) => {
      if (
        error instanceof Error &&
        /cs_migrations|schema "cipherstash"/i.test(error.message)
      ) {
        return null
      }
      throw error
    },
  )
  return last && !isReverseMigrationPhase(last.phase) ? last : null
}

/**
 * Whether the latest reverse event belongs to the lifecycle in progress, as
 * opposed to an earlier one that finished.
 *
 * `decrypt-dual-writing`, `decrypting` and `decrypted` are always current.
 * `encrypted-dropped` is recorded when the drop migration is GENERATED, and
 * the encrypted column still exists (it is being resolved), so it means one
 * of two things: the migration has not been applied, or its apply-time check
 * aborted. That is still the same lifecycle. Or the column was dropped and
 * later encrypted again: then the forward lifecycle that re-encrypted it has
 * recorded events under the twin's name AFTER the drop. Event ids are
 * monotonic, so the order tells them apart.
 */
export function isActiveReverseLifecycle(
  state: MigrationStateRow | null,
  forwardOfRecordedTwin: MigrationStateRow | null,
): boolean {
  if (state === null) return false
  if (state.phase !== 'encrypted-dropped') return true
  return (
    forwardOfRecordedTwin === null ||
    BigInt(forwardOfRecordedTwin.id) < BigInt(state.id)
  )
}

/**
 * The plaintext name derived from the encrypted column's own name when
 * nothing better is known: the `<name>_encrypted` convention stripped, else
 * `<encrypted>_plaintext`, so a derived name never collides with the
 * encrypted column itself. Shared by every command that shows a twin name.
 */
export function derivePlaintextName(encryptedColumn: string): {
  name: string
  via: 'convention' | 'fallback'
} {
  const suffix = '_encrypted'
  return encryptedColumn.endsWith(suffix) &&
    encryptedColumn.length > suffix.length
    ? { name: encryptedColumn.slice(0, -suffix.length), via: 'convention' }
    : { name: `${encryptedColumn}_plaintext`, via: 'fallback' }
}

/** `details.plaintextColumn` from a reverse event, when it recorded one. */
export function recordedPlaintextColumn(
  state: MigrationStateRow | null,
): string | undefined {
  const value = state?.details?.plaintextColumn
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

/**
 * Resolve an encrypted column and the plaintext twin it reverses into.
 *
 * The SOURCE must be an EQL v3 column — named explicitly, never guessed —
 * because the reverse lifecycle starts from what exists. The TARGET's name is
 * decided in this order:
 *
 * 1. `--plaintext-column`, when given;
 * 2. the pairing the reverse lifecycle IN PROGRESS recorded in
 *    `cs_migrations` — a flag that disagrees with it is refused rather than
 *    silently switching which column the lifecycle fills (and which column
 *    `decrypt drop`'s coverage gate then checks). A pairing from an earlier,
 *    finished lifecycle is not binding (see {@link isActiveReverseLifecycle});
 * 3. the forward manifest's entry whose `encryptedColumn` is this column —
 *    the original plaintext name, which is what most reversals want back;
 * 4. the `<name>_encrypted` convention, stripped;
 * 5. `<encrypted>_plaintext`, so a name that cannot be derived never
 *    collides with the encrypted column itself.
 *
 * Throws {@link BackfillConfigError} (printed verbatim by the commands) for a
 * source that is missing or not EQL v3, and for a target that is itself an
 * EQL column.
 */
export async function resolveDecryptPair(
  client: pg.ClientBase,
  opts: {
    table: string
    encryptedColumn: string
    plaintextColumn?: string
  },
): Promise<DecryptPair> {
  const { table, encryptedColumn } = opts

  const candidates = await listEncryptedColumns(client, table)
  const source = candidates.find((c) => c.column === encryptedColumn)
  if (!source) {
    if (!(await columnExists(client, table, encryptedColumn))) {
      throw new BackfillConfigError(
        `Column ${encryptedColumn} does not exist on ${table}. Pass the ENCRYPTED column with --column (the EQL v3 column you want to move back to plaintext).${candidates.length > 0 ? ` EQL v3 columns on ${table}: ${candidates.map((c) => c.column).join(', ')}.` : ''}`,
      )
    }
    throw new BackfillConfigError(
      `${table}.${encryptedColumn} is not an EQL v3 column, so there is nothing to decrypt. Pass the ENCRYPTED column with --column.${candidates.length > 0 ? ` EQL v3 columns on ${table}: ${candidates.map((c) => c.column).join(', ')}.` : ''}`,
    )
  }

  const state = await reverseState(client, table, encryptedColumn)
  const recordedTwin = recordedPlaintextColumn(state)
  const recordedForward =
    recordedTwin === undefined
      ? null
      : await forwardState(client, table, recordedTwin)
  const lifecycleActive = isActiveReverseLifecycle(state, recordedForward)
  const recorded = lifecycleActive ? recordedTwin : undefined

  let plaintextColumn: string
  let via: PlaintextResolution
  if (opts.plaintextColumn !== undefined) {
    if (recorded !== undefined && recorded !== opts.plaintextColumn) {
      throw new BackfillConfigError(
        `${table}.${encryptedColumn} is already being reversed into "${recorded}" (recorded in cipherstash.cs_migrations), but --plaintext-column is "${opts.plaintextColumn}". Refusing to switch targets mid-lifecycle: the coverage check before the encrypted column is dropped would then verify the wrong column. Drop the flag to continue with "${recorded}".`,
      )
    }
    plaintextColumn = opts.plaintextColumn
    via = 'flag'
  } else if (recorded !== undefined) {
    plaintextColumn = recorded
    via = 'recorded'
  } else {
    const fromManifest = await manifestPlaintextFor(table, encryptedColumn)
    if (fromManifest) {
      plaintextColumn = fromManifest
      via = 'manifest'
    } else {
      ;({ name: plaintextColumn, via } = derivePlaintextName(encryptedColumn))
    }
  }

  if (plaintextColumn === encryptedColumn) {
    throw new BackfillConfigError(
      `The plaintext column cannot be the encrypted column itself (${encryptedColumn}). Pass --plaintext-column <name>.`,
    )
  }
  if ((await detectColumnEqlVersion(client, table, plaintextColumn)) !== null) {
    throw new BackfillConfigError(
      `${table}.${plaintextColumn} is itself an EQL v3 column, so it cannot hold plaintext. Pass --plaintext-column <name> to choose another target.`,
    )
  }

  return {
    table,
    encryptedColumn,
    domain: source.domain,
    mapping: plaintextTypeForEqlDomain(source.domain),
    plaintextColumn,
    via,
    plaintextSqlType: await columnSqlType(client, table, plaintextColumn),
    state,
    lifecycleActive,
    forwardState:
      plaintextColumn === recordedTwin
        ? recordedForward
        : await forwardState(client, table, plaintextColumn),
  }
}

/**
 * Why a plaintext twin that already exists cannot be trusted as-is when a
 * reverse lifecycle starts:
 *
 * - `forward-source` — it is the column a forward encryption started from,
 *   and that lifecycle never reached `dropped`. Its values are the plaintext
 *   from before the switch, stale for every row the application updated
 *   after it stopped writing this column.
 * - `prepopulated` — it already holds values, from wherever.
 *
 * The reverse backfill only fills NULLs, so either way it would keep those
 * values, record `decrypted`, and let `decrypt drop` destroy the only current
 * copy, in the encrypted column.
 */
export type TwinHazard =
  | {
      kind: 'forward-source'
      forwardPhase: MigrationPhase
      hasValues: boolean
    }
  | { kind: 'prepopulated' }

/**
 * Check a twin before the FIRST reverse run trusts it. Returns `null` when
 * there is nothing to check (the twin does not exist yet, or a reverse
 * lifecycle is already in progress, so its values came from this lifecycle's
 * own backfill and dual-writes) or nothing wrong.
 */
export async function assessExistingTwin(
  client: pg.ClientBase,
  pair: DecryptPair,
): Promise<TwinHazard | null> {
  if (pair.lifecycleActive || pair.plaintextSqlType === null) return null
  const hasValues = await columnHasValues(
    client,
    pair.table,
    pair.plaintextColumn,
  )
  if (pair.forwardState !== null && pair.forwardState.phase !== 'dropped') {
    return {
      kind: 'forward-source',
      forwardPhase: pair.forwardState.phase,
      hasValues,
    }
  }
  return hasValues ? { kind: 'prepopulated' } : null
}

/** The two ways past a {@link TwinHazard}, as `decrypt backfill` flags. */
export const TWIN_HAZARD_FLAGS = {
  overwrite: '--force',
  keep: '--confirm-plaintext-current',
} as const

/**
 * The refusal (in `decrypt backfill`) or warning (in `decrypt plan`) for a
 * {@link TwinHazard}. Names and phases only, never a value.
 */
export function twinHazardMessage(
  pair: Pick<DecryptPair, 'table' | 'encryptedColumn' | 'plaintextColumn'>,
  hazard: TwinHazard,
): string {
  const twin = `${pair.table}.${pair.plaintextColumn}`
  const source = `${pair.table}.${pair.encryptedColumn}`
  const why =
    hazard.kind === 'forward-source'
      ? `${twin} is the source column of a forward encryption into ${pair.encryptedColumn} that was never dropped (forward phase '${hazard.forwardPhase}' in cipherstash.cs_migrations).${hazard.hasValues ? ' It still holds the plaintext from before reads moved to the encrypted column.' : ''} If your application stopped writing ${pair.plaintextColumn} at that switch, every row updated since then has a stale value in it.`
      : `${twin} already holds values, and no reverse migration is in progress for ${source}. Nothing records where they came from or whether they are current.`
  return [
    why,
    `The reverse backfill only fills rows where ${pair.plaintextColumn} is NULL, so it would keep those values, mark the column decrypted, and \`stash decrypt drop\` would then drop ${pair.encryptedColumn}: the only current copy.`,
    'Choose one, once the application writes BOTH columns on every insert and update:',
    `  ${TWIN_HAZARD_FLAGS.overwrite}  overwrite every row of ${pair.plaintextColumn} with the decrypted ciphertext (the safe choice when in doubt).`,
    `  ${TWIN_HAZARD_FLAGS.keep}  keep the existing values. Only when the application has written ${pair.plaintextColumn} on every insert and update for the whole time ${pair.encryptedColumn} existed.`,
  ].join('\n')
}

/**
 * The forward manifest's plaintext name for this encrypted column: the entry
 * whose recorded `encryptedColumn` is it, or — for entries written before that
 * field existed — whose `<column>_encrypted` convention names it.
 */
export async function manifestPlaintextFor(
  table: string,
  encryptedColumn: string,
): Promise<string | undefined> {
  const manifest = await readManifest()
  const entries = manifest?.tables[table] ?? []
  const entry =
    entries.find((e) => e.encryptedColumn === encryptedColumn) ??
    entries.find(
      (e) =>
        e.encryptedColumn === undefined &&
        `${e.column}_encrypted` === encryptedColumn,
    )
  return entry?.column
}
