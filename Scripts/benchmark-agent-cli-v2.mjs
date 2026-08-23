#!/usr/bin/env node

import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const [fixtureRoot, baselineRoot, rankFile] = process.argv.slice(2)
if (!fixtureRoot || !baselineRoot || !rankFile) {
  process.stderr.write(
    'usage: benchmark-agent-cli-v2.mjs <fixture-root> <compact-json-v1-root> <o200k_base.tiktoken>\n',
  )
  process.exit(2)
}

const contraction = String.raw`'(?:[sS]|[dD]|[mM]|[tT]|[lL][lL]|[vV][eE]|[rR][eE])`
const optionalContraction = String.raw`(?:${contraction})?`
const splitPattern = String.raw`[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+${optionalContraction}|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*${optionalContraction}|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n/]*|\s*[\r\n]+|\s+(?!\S)|\s+`
const tokenSplit = new RegExp(splitPattern, 'gu')
const utf8 = new TextEncoder()

const ranks = new Map()
for (const line of fs.readFileSync(rankFile, 'utf8').trim().split('\n')) {
  const [encoded, rank] = line.split(' ')
  ranks.set(Buffer.from(encoded, 'base64').toString('hex'), Number(rank))
}

function merged(left, right) {
  const value = new Uint8Array(left.length + right.length)
  value.set(left)
  value.set(right, left.length)
  return value
}

function countChunk(chunk) {
  const bytes = utf8.encode(chunk)
  if (ranks.has(Buffer.from(bytes).toString('hex'))) return 1

  const pieces = Array.from(bytes, (byte) => Uint8Array.of(byte))
  while (pieces.length > 1) {
    let bestIndex = -1
    let bestRank = Number.POSITIVE_INFINITY
    for (let index = 0; index < pieces.length - 1; index += 1) {
      const rank = ranks.get(Buffer.from(merged(pieces[index], pieces[index + 1])).toString('hex'))
      if (rank !== undefined && rank < bestRank) {
        bestRank = rank
        bestIndex = index
      }
    }
    if (bestIndex < 0) break
    pieces.splice(bestIndex, 2, merged(pieces[bestIndex], pieces[bestIndex + 1]))
  }
  return pieces.length
}

function countTokens(text) {
  let reconstructed = ''
  let count = 0
  for (const match of text.matchAll(tokenSplit)) {
    reconstructed += match[0]
    count += countChunk(match[0])
  }
  assert.equal(reconstructed, text, 'token split did not consume the complete document')
  return count
}

const upstreamCountChecks = new Map([
  ['', 0],
  [' ', 1],
  ['\t', 1],
  ['This is some text', 4],
  ['indivisible', 3],
  ['hello 👋 world 🌍', 6],
  ["What's", 1],
  ['hello, I am a text, and I have commas. a,b,c', 15],
])
for (const [sample, expected] of upstreamCountChecks) {
  assert.equal(countTokens(sample), expected, `o200k_base self-check failed for ${sample}`)
}

const baselineFiles = fs
  .readdirSync(baselineRoot)
  .filter((name) => name.endsWith('.json'))
  .sort()
assert.ok(baselineFiles.length > 0, 'no legacy compact JSON baseline fixtures found')

const rows = baselineFiles.map((baselineName) => {
  const name = baselineName.replace(/\.json$/, '.toon')
  assert.ok(fs.existsSync(path.join(fixtureRoot, name)), `missing TOON fixture for ${baselineName}`)
  assert.ok(
    fs.existsSync(path.join(fixtureRoot, baselineName)),
    `missing same-semantics JSON fixture for ${baselineName}`,
  )
  const toon = fs.readFileSync(path.join(fixtureRoot, name), 'utf8').replace(/\n$/, '')
  const equivalentJSON = JSON.stringify(
    JSON.parse(fs.readFileSync(path.join(fixtureRoot, baselineName), 'utf8')),
  )
  const v1JSON = JSON.stringify(
    JSON.parse(fs.readFileSync(path.join(baselineRoot, baselineName), 'utf8')),
  )
  const toonTokens = countTokens(toon)
  const equivalentJSONTokens = countTokens(equivalentJSON)
  const v1JSONTokens = countTokens(v1JSON)
  return {
    name: name.replace(/\.toon$/, ''),
    toonTokens,
    equivalentJSONTokens,
    v1JSONTokens,
    migrationSavings: ((v1JSONTokens - toonTokens) / v1JSONTokens) * 100,
  }
})

const totalToon = rows.reduce((sum, row) => sum + row.toonTokens, 0)
const totalEquivalentJSON = rows.reduce((sum, row) => sum + row.equivalentJSONTokens, 0)
const totalV1JSON = rows.reduce((sum, row) => sum + row.v1JSONTokens, 0)
const totalMigrationSavings = ((totalV1JSON - totalToon) / totalV1JSON) * 100

process.stdout.write(
  '| Fixture | TOON v2 | Same-semantics compact JSON | Legacy compact JSON v1 | v1 → TOON |\n',
)
process.stdout.write('|---|---:|---:|---:|---:|\n')
for (const row of rows) {
  process.stdout.write(
    `| ${row.name} | ${row.toonTokens} | ${row.equivalentJSONTokens} | ${row.v1JSONTokens} | ${row.migrationSavings.toFixed(1)}% |\n`,
  )
}
process.stdout.write(
  `| **Total** | **${totalToon}** | **${totalEquivalentJSON}** | **${totalV1JSON}** | **${totalMigrationSavings.toFixed(1)}%** |\n`,
)

if (!(totalToon < totalV1JSON)) {
  process.stderr.write('The AXI v2 migration did not reduce aggregate legacy v1 tokens.\n')
  process.exit(1)
}
