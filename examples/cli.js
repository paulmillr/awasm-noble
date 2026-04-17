#!/usr/bin/env node
import { blake3 } from '@awasm/noble/wasm_threads.js';
import fs from 'node:fs';
import os from 'node:os';
import process from 'node:process';

const CHUNK_SIZE = 1024 * 1024 * 10;

const hashStream = async (stream) => {
  const hasher = blake3.create();
  for await (const chunk of stream) {
    hasher.update(chunk);
  }
  return hasher.digest();
};

const mapLimit = async (items, limit, mapFn) => {
  const results = new Array(items.length);
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const current = index;
      index += 1;
      if (current >= items.length) return;
      results[current] = await mapFn(items[current], current);
    }
  });
  await Promise.all(workers);
  return results;
};

async function checksumInput(name) {
  const stream = name === '-' ? process.stdin : fs.createReadStream(name, { highWaterMark: CHUNK_SIZE });
  const digest = await hashStream(stream);
  return `${digest.toHex()}  ${name}`;
}

async function main() {
  const files = process.argv.slice(2);
  if (!files.length) files.push('-');

  if (files.filter((file) => file === '-').length > 1) {
    process.stderr.write('cli: stdin (-) can only be used once\n');
    process.exitCode = 1;
    return;
  }

  const concurrency = files.includes('-')
    ? 1
    : Math.max(1, Math.min(files.length, os.availableParallelism()));

  const results = await mapLimit(files, concurrency, async (file) => {
    try {
      const output = await checksumInput(file);
      return { file, output };
    } catch (error) {
      return { file, error };
    }
  });

  let failed = false;
  for (const result of results) {
    if (result.error) {
      failed = true;
      process.stderr.write(`cli: ${result.file}: ${result.error.message}\n`);
      continue;
    }
    process.stdout.write(`${result.output}\n`);
  }
  if (failed) process.exitCode = 1;
}

await main();
