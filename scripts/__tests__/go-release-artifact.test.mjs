import { execFileSync, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `release-golang.yml`'s `publish` job holds `contents: write` and builds the
 * release commit from an artifact made by `build`, the job that runs
 * third-party code (cargo build scripts, proc macros, the Go tests) AFTER it
 * writes `guests.sha256`. So the manifest is untrusted input to `publish`. If
 * `publish` took its paths from the manifest, a build-time compromise could
 * add a line for, say, `languages/golang/encrypt/init.go` and ship it on the
 * tag; the tree comparison would pass, because `build` derived the tree it
 * reports from the same manifest.
 *
 * These tests run the real "Commit the guests" step against forged artifacts.
 */

const WORKFLOW = readWorkflow('.github/workflows/release-golang.yml')
const GUESTS = String(WORKFLOW.env.GUESTS).split(/\s+/).filter(Boolean)
const COMMIT_STEP = WORKFLOW.jobs.publish.steps.find(
  (step) => step.name === 'Commit the guests',
)

const git = (cwd, ...args) =>
  execFileSync('git', args, { cwd, encoding: 'utf8' }).trim()

/**
 * The step runs on Linux, where `install -D` is GNU coreutils. macOS ships BSD
 * `install`, which has no `-D`; a Homebrew coreutils install provides GNU's as
 * `ginstall`, and the step sees it as `install` through a shim directory.
 * Without either, the commit case cannot run here and is skipped; the refusal
 * cases stop before `install` and run everywhere.
 */
const GNU_INSTALL = ['install', 'ginstall'].find((name) => {
  const probe = spawnSync(name, ['--version'], { encoding: 'utf8' })
  return probe.status === 0 && probe.stdout.includes('GNU coreutils')
})
const SHIMS = mkdtempSync(join(tmpdir(), 'go-release-artifact-bin-'))
if (GNU_INSTALL === 'ginstall') {
  const path = execFileSync('bash', ['-c', 'command -v ginstall'], {
    encoding: 'utf8',
  }).trim()
  symlinkSync(path, join(SHIMS, 'install'))
}

afterAll(() => {
  rmSync(SHIMS, { recursive: true, force: true })
})

const sha256 = (cwd, path) =>
  execFileSync('sha256sum', [path], { cwd, encoding: 'utf8' }).trim()

let repo

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), 'go-release-artifact-'))
  git(repo, 'init', '-q', '-b', 'main')
  git(repo, 'config', 'user.name', 'test')
  git(repo, 'config', 'user.email', 'test@example.com')
  git(repo, 'config', 'commit.gpgsign', 'false')
  writeFileSync(join(repo, '.gitignore'), '*.wasm\n')
  git(repo, 'add', '.gitignore')
  git(repo, 'commit', '-q', '-m', 'source')
})

afterEach(() => {
  rmSync(repo, { recursive: true, force: true })
})

/** Put `path` in the artifact with `body`. Returns its manifest line. */
function stage(path, body) {
  const at = join(repo, 'release-out', path)
  mkdirSync(dirname(at), { recursive: true })
  writeFileSync(at, body)
  return sha256(join(repo, 'release-out'), path)
}

/** The honest manifest: one line per guest, in GUESTS order. */
function honestManifest() {
  return GUESTS.map((guest) => stage(guest, `guest ${guest}\n`))
}

function writeManifest(lines) {
  writeFileSync(
    join(repo, 'release-out/guests.sha256'),
    `${lines.join('\n')}\n`,
  )
}

/** The tree the release commit should have: HEAD plus the three guests. */
function expectedTree() {
  const index = join(repo, '.git', 'expected-index')
  const env = { ...process.env, GIT_INDEX_FILE: index }
  execFileSync('git', ['read-tree', 'HEAD'], { cwd: repo, env })
  for (const guest of GUESTS) {
    const blob = git(repo, 'hash-object', '-w', join('release-out', guest))
    execFileSync(
      'git',
      ['update-index', '--add', '--cacheinfo', `100644,${blob},${guest}`],
      { cwd: repo, env },
    )
  }
  return execFileSync('git', ['write-tree'], {
    cwd: repo,
    env,
    encoding: 'utf8',
  }).trim()
}

function runCommitStep(tree) {
  return spawnSync('bash', ['-c', String(COMMIT_STEP.run)], {
    cwd: repo,
    encoding: 'utf8',
    env: {
      PATH: `${SHIMS}:${process.env.PATH}`,
      HOME: repo,
      GIT_CONFIG_NOSYSTEM: '1',
      GUESTS: WORKFLOW.env.GUESTS,
      VERSION: '0.1.0-alpha.1',
      TREE: tree,
      GITHUB_SHA: git(repo, 'rev-parse', 'HEAD'),
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'cipherstash/stack',
      GITHUB_RUN_ID: '1',
    },
  })
}

describe('release-golang.yml publish: Commit the guests', () => {
  it('exists, and the publish job takes its paths from GUESTS', () => {
    expect(COMMIT_STEP).toBeDefined()
    expect(GUESTS).toHaveLength(3)
    expect(String(COMMIT_STEP.run)).toContain('"$GUESTS"')
  })

  it.skipIf(!GNU_INSTALL)(
    'commits the three guests from an honest artifact',
    () => {
      writeManifest(honestManifest())
      const tree = expectedTree()
      const result = runCommitStep(tree)
      expect(result.stderr + result.stdout).not.toContain('::error::')
      expect(result.status).toBe(0)
      expect(git(repo, 'rev-parse', 'HEAD^{tree}')).toBe(tree)
      expect(
        git(repo, 'show', '--name-only', '--format=', 'HEAD').split('\n'),
      ).toEqual([...GUESTS].sort())
    },
  )

  it.each([
    [
      'an extra path',
      (lines) => [
        ...lines,
        stage('languages/golang/encrypt/init.go', 'package encrypt\n'),
      ],
    ],
    [
      'a substituted path',
      (lines) => [
        lines[0],
        lines[1],
        stage('languages/golang/auth/init.go', 'package auth\n'),
      ],
    ],
    [
      'a path outside the module',
      (lines) => [
        lines[0],
        lines[1],
        stage('.github/workflows/x.yml', 'on: push\n'),
      ],
    ],
    ['a missing guest', (lines) => lines.slice(0, 2)],
    ['the guests out of order', (lines) => [lines[1], lines[0], lines[2]]],
    [
      'a BSD-format line sha256sum -c would also accept',
      (lines) => {
        const [hash, path] = lines[2].split('  ')
        return [lines[0], lines[1], `SHA256 (${path}) = ${hash}`]
      },
    ],
  ])('refuses a manifest with %s before copying anything', (_, forge) => {
    const honest = honestManifest()
    // The tree a compromised build would report for its forged manifest is
    // whatever it likes; give the step the honest tree so only the manifest
    // check can stop it.
    const tree = expectedTree()
    const head = git(repo, 'rev-parse', 'HEAD')
    writeManifest(forge(honest))

    const result = runCommitStep(tree)

    expect(result.status).not.toBe(0)
    expect(result.stdout).toContain('::error::guests.sha256')
    expect(git(repo, 'rev-parse', 'HEAD')).toBe(head)
    for (const path of [
      ...GUESTS,
      'languages/golang/encrypt/init.go',
      'languages/golang/auth/init.go',
      '.github/workflows/x.yml',
    ]) {
      expect(existsSync(join(repo, path)), path).toBe(false)
    }
  })
})
