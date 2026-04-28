#!/usr/bin/env node
import net from 'node:net';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

function usage() {
  console.error(`Usage:
  hostcmd_client.mjs submit [--socket <path>] --request-id <id|auto> --command <cmd> [--arg <arg>]... --reason <reason> [--timeout-sec <sec>]
  hostcmd_client.mjs query [--socket <path>] --request-id <id>`);
}

function parseArgs(argv) {
  if (argv.length === 0) {
    usage();
    process.exit(2);
  }

  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const skillDir = path.dirname(scriptDir);
  const defaultSocket = process.env.HOSTCMD_SOCKET || path.join(skillDir, 'hostcmd.sock');

  const subcommand = argv[0];
  const opts = {
    socket: defaultSocket,
    requestId: 'auto',
    command: '',
    args: [],
    reason: '',
    timeoutSec: 30,
  };

  for (let i = 1; i < argv.length; i += 1) {
    let k = argv[i];
    let v = argv[i + 1];
    let inline = false;

    // Support --key=value style (useful for values like -al).
    if (k.startsWith('--') && k.includes('=')) {
      const idx = k.indexOf('=');
      v = k.slice(idx + 1);
      k = k.slice(0, idx);
      inline = true;
    }

    if (k === '--socket') {
      opts.socket = v;
      if (!inline) i += 1;
    } else if (k === '--request-id') {
      opts.requestId = v;
      if (!inline) i += 1;
    } else if (k === '--command') {
      opts.command = v;
      if (!inline) i += 1;
    } else if (k === '--arg') {
      opts.args.push(v);
      if (!inline) i += 1;
    } else if (k === '--reason') {
      opts.reason = v;
      if (!inline) i += 1;
    } else if (k === '--timeout-sec') {
      opts.timeoutSec = Number(v);
      if (!inline) i += 1;
    } else {
      console.error(`Unknown option: ${k}`);
      usage();
      process.exit(2);
    }
  }

  return { subcommand, opts };
}

function genRequestId() {
  return `req-${Math.floor(Date.now() / 1000)}-${randomUUID().replaceAll('-', '').slice(0, 12)}`;
}

function buildPayload(subcommand, opts) {
  const requestId = opts.requestId === 'auto' ? genRequestId() : opts.requestId;
  if (subcommand === 'submit') {
    if (!opts.command || !opts.reason) {
      console.error('submit requires --command and --reason');
      process.exit(2);
    }
    return {
      action: 'submit',
      request_id: requestId,
      command: opts.command,
      args: opts.args,
      reason: opts.reason,
      timeout_sec: opts.timeoutSec,
    };
  }

  if (subcommand === 'query') {
    if (!requestId || requestId === 'auto') {
      console.error('query requires --request-id');
      process.exit(2);
    }
    return {
      action: 'query',
      request_id: requestId,
    };
  }

  console.error(`Unknown subcommand: ${subcommand}`);
  usage();
  process.exit(2);
}

function sendJsonl(socketPath, payload) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: socketPath });
    let buffer = '';

    client.on('connect', () => {
      client.write(`${JSON.stringify(payload)}\n`);
    });

    client.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const idx = buffer.indexOf('\n');
      if (idx >= 0) {
        const line = buffer.slice(0, idx);
        client.end();
        try {
          resolve(JSON.parse(line));
        } catch (err) {
          reject(err);
        }
      }
    });

    client.on('error', (err) => reject(err));
    client.on('end', () => {
      if (!buffer.includes('\n')) {
        reject(new Error('connection closed before newline response'));
      }
    });
  });
}

async function main() {
  const { subcommand, opts } = parseArgs(process.argv.slice(2));
  const payload = buildPayload(subcommand, opts);
  const resp = await sendJsonl(opts.socket, payload);
  console.log(JSON.stringify(resp, null, 2));
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
