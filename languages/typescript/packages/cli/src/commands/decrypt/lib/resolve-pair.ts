import {
  columnExists,
  columnSqlType,
  detectColumnEqlVersion,
  isReverseMigrationPhase,
  listEncryptedColumns,
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
  /** Latest REVERSE event for this encrypted column, if any. */
  state: MigrationStateRow | null
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
 * 2. the pairing a previous reverse run RECORDED in `cs_migrations` — a flag
 *    that disagrees with it is refused rather than silently switching which
 *    column the lifecycle fills (and which column `decrypt drop`'s coverage
 *    gate then checks);
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
  const recorded = recordedPlaintextColumn(state)

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
    } else if (
      encryptedColumn.endsWith('_encrypted') &&
      encryptedColumn.length > '_encrypted'.length
    ) {
      plaintextColumn = encryptedColumn.slice(0, -'_encrypted'.length)
      via = 'convention'
    } else {
      plaintextColumn = `${encryptedColumn}_plaintext`
      via = 'fallback'
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
  }
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
