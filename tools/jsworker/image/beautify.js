#!/usr/bin/env node
// Re-print a JavaScript file with one statement per line and normal indentation.
// Layout only: no renaming, no constant folding, no deobfuscation.
//   node /opt/jsre/beautify.js IN.js OUT.js
'use strict';
const fs = require('fs');
const parser = require('@babel/parser');
const generate = require('@babel/generator').default;

const [, , inPath, outPath] = process.argv;
if (!inPath || !outPath) {
  console.error('usage: beautify.js IN.js OUT.js');
  process.exit(2);
}
const src = fs.readFileSync(inPath, 'utf8');
const ast = parser.parse(src, { sourceType: 'script', allowReturnOutsideFunction: true, errorRecovery: false });
const out = generate(ast, { compact: false, comments: true, retainLines: false, jsescOption: { minimal: true } }, src).code;
fs.writeFileSync(outPath, out + '\n');
console.log('wrote %s (%d bytes, %d lines)', outPath, Buffer.byteLength(out), out.split('\n').length);
