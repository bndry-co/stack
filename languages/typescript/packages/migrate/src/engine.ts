import type { ClientBase, PoolClient } from 'pg'
import type { KeysetPage } from './cursor.js'
import {
  appendEvent,
  type MigrationEvent,
  type MigrationPhase,
  progress,
} from './state.js'

/**
 * The `cs_migrations` vocabulary one direction of the lifecycle writes. The
 * forward backfill and the reverse (decrypt) backfill run the same engine and
 * differ here, so their histories stay distinguishable and neither resumes
 * from the other's cursor.
 */
export interface ChunkedRunEvents {
  started: MigrationEvent
  /** The event a resume looks for. Its `cursorValue` is the restart point. */
  checkpoint: MigrationEvent
  completed: MigrationEvent
  /** Phase recorded on `started`, every `checkpoint`, and any `error`. */
  runningPhase: MigrationPhase
  completedPhase: MigrationPhase
}

/**
 * A chunk whose network work (encrypt or decrypt) is done and whose database
 * write is ready to run inside the chunk's transaction.
 */
export interface PreparedChunk {
  /** Issue the chunk's writes on `db`. Runs between `BEGIN` and `COMMIT`. */
  write(db: ClientBase): Promise<void>
  /**
   * Rows in this chunk that were visited but deliberately not written — for
   * the reverse direction, values that could not be decrypted. Counted only
   * when {@link ChunkedRunOptions.trackSkipped} is set.
   */
  skipped?: number
  /** Extra fields merged into this chunk's checkpoint event `details`. */
  checkpointDetails?: Record<string, unknown>
}

/** Context handed to {@link ChunkedRunOptions.prepareChunk}. */
export interface ChunkContext {
  /** Zero-based index of this chunk within the current run. */
  chunkIndex: number
  /** True when this run resumed from a recorded checkpoint. */
  resumed: boolean
}

/** Progress snapshot, emitted after every committed chunk. */
export interface ChunkedRunProgress {
  rowsProcessed: number
  rowsTotal: number
  lastPk: string | null
  chunkSize: number
  chunkIndex: number
  /** Cumulative skipped rows; always `0` unless skipping is tracked. */
  rowsSkipped: number
}

export interface ChunkedRunOptions<Row extends { pk: string }> {
  db: PoolClient
  tableName: string
  /** The `column_name` this run's events are recorded under. */
  stateColumn: string
  chunkSize: number
  signal?: AbortSignal
  events: ChunkedRunEvents
  /** Rows still to process, for `rowsTotal`. Evaluated once, at start. */
  countPending(): Promise<number>
  /** The next keyset page after `after` (exclusive). */
  fetchPage(after: string | null, limit: number): Promise<KeysetPage<Row>>
  /**
   * Do the chunk's network work BEFORE the transaction opens, so a slow
   * ZeroKMS round trip never holds row locks. Throwing aborts the run (an
   * `error` event is recorded and the error rethrown) with nothing written
   * for this chunk and the cursor where it was.
   */
  prepareChunk(rows: Row[], context: ChunkContext): Promise<PreparedChunk>
  /** Extra fields merged into the `started` event's `details`. */
  startedDetails?: Record<string, unknown>
  /**
   * Fields merged into EVERY event's `details` (started, checkpoint,
   * completed, error) — e.g. the reverse run records which plaintext column
   * it fills, so later commands can recover the pairing from state alone.
   */
  baseDetails?: Record<string, unknown>
  /**
   * Maintain a cumulative `rowsSkipped` (restored from the resumed checkpoint)
   * and record it on checkpoint/completed events. Off for the forward
   * backfill, whose event details are pinned by existing history readers.
   */
  trackSkipped?: boolean
  onProgress?: (progress: ChunkedRunProgress) => void
}

export interface ChunkedRunResult {
  resumed: boolean
  rowsProcessed: number
  rowsTotal: number
  completed: boolean
  rowsSkipped: number
}

/**
 * The chunked, resumable, keyset-paginated loop both backfill directions run.
 *
 * Per chunk: fetch the next page after the cursor, prepare it (network work,
 * outside any transaction), then in ONE transaction write it and append a
 * checkpoint event, and commit. The checkpoint and the data land atomically,
 * so a crash can never record progress for rows that were not written, and
 * the `target IS NULL` guard in every page query makes a lost cursor
 * harmless: a re-run simply re-selects whatever is still pending.
 *
 * Resume: when the column's latest event is this direction's checkpoint, the
 * run restarts from its cursor and carries its counters forward. Any other
 * latest event (a completed run, an error, the other direction's history)
 * starts a fresh pass from the beginning, which the idempotency guard keeps
 * cheap.
 *
 * Abort: `signal` is checked between chunks; the in-flight chunk always
 * finishes and checkpoints first.
 */
export async function runChunkedMigration<Row extends { pk: string }>(
  options: ChunkedRunOptions<Row>,
): Promise<ChunkedRunResult> {
  const { db, tableName, stateColumn, chunkSize, events } = options
  const base = options.baseDetails ?? {}
  const trackSkipped = options.trackSkipped ?? false

  const pending = await options.countPending()

  const last = await progress(db, tableName, stateColumn)
  const resumedFrom = last?.event === events.checkpoint ? last : null
  const resumeCursor = resumedFrom ? resumedFrom.cursorValue : null
  const resumed = resumeCursor !== null
  const priorProcessed = resumedFrom ? (resumedFrom.rowsProcessed ?? 0) : 0
  const priorSkipped =
    trackSkipped && resumedFrom ? readSkipped(resumedFrom.details) : 0

  const rowsTotal = priorProcessed + pending

  await appendEvent(db, {
    tableName,
    columnName: stateColumn,
    event: events.started,
    phase: events.runningPhase,
    cursorValue: resumeCursor,
    rowsProcessed: priorProcessed,
    rowsTotal,
    details: {
      ...base,
      chunkSize,
      resumed,
      ...options.startedDetails,
    },
  })

  let cursor = resumeCursor
  let rowsProcessed = priorProcessed
  let rowsSkipped = priorSkipped
  let chunkIndex = 0
  let completed = false
  const skippedDetails = () => (trackSkipped ? { rowsSkipped } : {})

  try {
    while (true) {
      if (options.signal?.aborted) break

      const page = await options.fetchPage(cursor, chunkSize)
      if (page.rows.length === 0) {
        completed = true
        break
      }

      const prepared = await options.prepareChunk(page.rows, {
        chunkIndex,
        resumed,
      })
      const chunkSkipped = trackSkipped ? (prepared.skipped ?? 0) : 0

      await db.query('BEGIN')
      try {
        await prepared.write(db)
        rowsProcessed += page.rows.length
        rowsSkipped += chunkSkipped
        cursor = page.lastPk
        await appendEvent(db, {
          tableName,
          columnName: stateColumn,
          event: events.checkpoint,
          phase: events.runningPhase,
          cursorValue: cursor,
          rowsProcessed,
          rowsTotal,
          details: {
            ...base,
            chunkIndex,
            chunkRows: page.rows.length,
            ...(trackSkipped ? { chunkSkipped } : {}),
            ...skippedDetails(),
            ...prepared.checkpointDetails,
          },
        })
        await db.query('COMMIT')
      } catch (err) {
        await db.query('ROLLBACK').catch(() => {})
        throw err
      }

      options.onProgress?.({
        rowsProcessed,
        rowsTotal,
        lastPk: cursor,
        chunkSize,
        chunkIndex,
        rowsSkipped,
      })
      chunkIndex += 1
    }

    if (completed) {
      await appendEvent(db, {
        tableName,
        columnName: stateColumn,
        event: events.completed,
        phase: events.completedPhase,
        cursorValue: cursor,
        rowsProcessed,
        rowsTotal,
        details: { ...base, chunkCount: chunkIndex, ...skippedDetails() },
      })
    }
  } catch (err) {
    await appendEvent(db, {
      tableName,
      columnName: stateColumn,
      event: 'error',
      phase: events.runningPhase,
      cursorValue: cursor,
      rowsProcessed,
      rowsTotal,
      details: {
        ...base,
        message: err instanceof Error ? err.message : String(err),
        chunkIndex,
      },
    })
    throw err
  }

  return { resumed, rowsProcessed, rowsTotal, completed, rowsSkipped }
}

/** Cumulative skipped count from a checkpoint's details; `0` when absent. */
function readSkipped(details: Record<string, unknown> | null): number {
  const value = details?.rowsSkipped
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}
