// Run one n8n Code-node script ("Run Once for All Items" mode) under Node with n8n's globals stubbed.
//
//   node run_code.mjs <script.js>  < context.json  > result.json
//
// context.json: {"env": {...}, "items": [{"json": {...}, "binary": {...}?}], "static": {...},
//                "http": [response, ...]}   // answers for this.helpers.httpRequest, in order; a string is thrown
// result.json:  {"output": [...items], "static": {...}, "requests": [...httpRequest options]}
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const ALLOWED = new Set(['crypto']); // mirrors NODE_FUNCTION_ALLOW_BUILTIN in deploy/docker-compose.yml
const sandboxRequire = (name) => {
  if (!ALLOWED.has(name)) throw new Error(`Cannot find module '${name}' (not in NODE_FUNCTION_ALLOW_BUILTIN)`);
  return require(name);
};

const source = readFileSync(process.argv[2], 'utf8');
const ctx = JSON.parse(readFileSync(0, 'utf8'));
const items = ctx.items || [];
const staticData = ctx.static || {};
const responses = [...(ctx.http || [])];
const requests = [];

const helpers = {
  async httpRequest(options) {
    requests.push(options);
    const next = responses.shift();
    if (next === undefined || typeof next === 'string') throw new Error(next || 'no stubbed response');
    return next;
  },
  async getBinaryDataBuffer(index, property) {
    return Buffer.from(items[index].binary[property].data, 'base64');
  },
};
const $input = { all: () => items, first: () => items[0] };
const $getWorkflowStaticData = () => staticData;

const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
const fn = new AsyncFunction('$env', '$input', '$getWorkflowStaticData', 'require', source);
const output = await fn.call({ helpers }, ctx.env || {}, $input, $getWorkflowStaticData, sandboxRequire);
process.stdout.write(JSON.stringify({ output, static: staticData, requests }));
