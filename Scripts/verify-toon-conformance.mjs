#!/usr/bin/env node

import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { pathToFileURL } from 'node:url'

const EXPECTED_SPEC_VERSION = '4.1.1'
const REQUIRED_PRODUCT_FIXTURES = [
  'alias-selection.required',
  'auto-docker.completed',
  'auto-root.completed',
  'auto-sudo-approval.required',
  'client-unavailable.failed',
  'direct-one-call.completed',
  'doctor.completed',
  'execution-truncated.failed',
  'home.completed',
  'policy-denied.failed',
  'protected-user-action.required',
  'resource-list.empty',
  'request-wait.completed',
  'resource-not-found.failed',
  'setup.no-op',
  'sudo-approval.required',
  'sudo-enrollment-user-action.required',
  'sudo-root.no-op',
  'sudo-status.completed',
  'topology-path.completed',
  'transport.failed',
  'usage-error.failed',
]

function failUsage() {
  process.stderr.write(
    'usage: verify-toon-conformance.mjs <reference-root> <spec-root> <safa-fixture-root>\n',
  )
  process.exit(2)
}

const [referenceRoot, specRoot, safaFixtureRoot] = process.argv.slice(2)
if (!referenceRoot || !specRoot || !safaFixtureRoot) failUsage()

const referencePackage = JSON.parse(
  fs.readFileSync(path.join(referenceRoot, 'packages/toon/package.json'), 'utf8'),
)
const specificationPackage = JSON.parse(
  fs.readFileSync(path.join(specRoot, 'package.json'), 'utf8'),
)
assert.equal(referencePackage.version, EXPECTED_SPEC_VERSION)
assert.equal(specificationPackage.version, EXPECTED_SPEC_VERSION)

const referenceEntry = pathToFileURL(
  path.join(referenceRoot, 'packages/toon/src/index.ts'),
).href
const { decode, encode } = await import(referenceEntry)

function sortedFiles(root, suffix) {
  return fs
    .readdirSync(root, { withFileTypes: true })
    .flatMap((entry) => {
      const candidate = path.join(root, entry.name)
      if (entry.isDirectory()) return sortedFiles(candidate, suffix)
      return entry.isFile() && entry.name.endsWith(suffix) ? [candidate] : []
    })
    .sort()
}

for (const fixture of REQUIRED_PRODUCT_FIXTURES) {
  assert.ok(
    fs.existsSync(path.join(safaFixtureRoot, `${fixture}.json`)),
    `missing required product fixture ${fixture}.json`,
  )
  assert.ok(
    fs.existsSync(path.join(safaFixtureRoot, `${fixture}.toon`)),
    `missing required product fixture ${fixture}.toon`,
  )
}

let productFixtureCount = 0
for (const toonPath of sortedFiles(safaFixtureRoot, '.toon')) {
  const expectedPath = toonPath.replace(/\.toon$/, '.json')
  assert.ok(fs.existsSync(expectedPath), `missing expected JSON for ${toonPath}`)

  const toon = fs.readFileSync(toonPath, 'utf8').replace(/\n$/, '')
  const expected = JSON.parse(fs.readFileSync(expectedPath, 'utf8'))
  const decoded = decode(toon, { strict: true })
  assert.deepEqual(decoded, expected, `strict decode mismatch: ${toonPath}`)
  assert.equal(encode(expected), toon, `non-canonical TOON: ${toonPath}`)
  productFixtureCount += 1
}
assert.ok(productFixtureCount > 0, 'no SAFA TOON fixtures found')

let officialEncodeCount = 0
const officialEncodeRoot = path.join(specRoot, 'tests/fixtures/encode')
for (const fixturePath of sortedFiles(officialEncodeRoot, '.json')) {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'))
  for (const test of fixture.tests) {
    if (test.shouldError) {
      assert.throws(() => encode(test.input, test.options), undefined, `${fixturePath}: ${test.name}`)
    } else {
      assert.equal(
        encode(test.input, test.options),
        test.expected,
        `${fixturePath}: ${test.name}`,
      )
    }
    officialEncodeCount += 1
  }
}

let officialStrictDecodeCount = 0
const officialDecodeRoot = path.join(specRoot, 'tests/fixtures/decode')
for (const fixturePath of sortedFiles(officialDecodeRoot, '.json')) {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'))
  for (const test of fixture.tests) {
    if (test.options?.strict === false) continue
    if (test.shouldError) {
      assert.throws(
        () => decode(test.input, { ...test.options, strict: true }),
        undefined,
        `${fixturePath}: ${test.name}`,
      )
    } else {
      assert.deepEqual(
        decode(test.input, { ...test.options, strict: true }),
        test.expected,
        `${fixturePath}: ${test.name}`,
      )
    }
    officialStrictDecodeCount += 1
  }
}

process.stdout.write(
  `TOON ${EXPECTED_SPEC_VERSION} conformance passed: `
    + `${productFixtureCount} SAFA fixtures strictly decoded, `
    + `${officialEncodeCount} official encode fixtures and `
    + `${officialStrictDecodeCount} official strict-decode fixtures verified.\n`,
)
