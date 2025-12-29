const express = require('express');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const vm = require('vm');
const net = require('net');
const dns = require('dns');
const os = require('os');
const serialize = require('node-serialize');
const Long = require('long');
const utf8 = require('utf8');
const { glob } = require('glob');
const timer = require('@szmarczak/http-timer');
const address = require('address');
const { codeFrameColumns } = require('@babel/code-frame');

// Vulnerable dependencies
const _ = require('lodash');
const moment = require('moment');
const axios = require('axios');
const minimist = require('minimist');
const request = require('request');
const tar = require('tar');
const handlebars = require('handlebars');
const ejs = require('ejs');
const marked = require('marked');
const debug = require('debug');
const shelljs = require('shelljs');
const validator = require('validator');
const dotProp = require('dot-prop');

// @babel group
const babelCore = require('@babel/core');
const babelParser = require('@babel/parser');
const babelTypes = require('@babel/types');
const babelHelperValidator = require('@babel/helper-validator-identifier');

// Webpack group
const webpack = require('webpack');

// Framework groups
const React = require('react');
const ReactDOM = require('react-dom');

// Utilities with vulnerabilities
const semver = require('semver');
const ini = require('ini');
const y18n = require('y18n');
const elliptic = require('elliptic');
const UAParser = require('ua-parser-js');
const ansiRegex = require('ansi-regex');
const trim = require('trim');
const pathParse = require('path-parse');
const crossFetch = require('cross-fetch');
const forge = require('node-forge');
const WebSocket = require('ws');
const dnsPacket = require('dns-packet');
const browserslist = require('browserslist');

// @webassemblyjs group
const wasmParser = require('@webassemblyjs/wasm-parser');
const wasmGen = require('@webassemblyjs/wasm-gen');
const wasmAst = require('@webassemblyjs/ast');

// @xtuc group
const xtucIeee754 = require('@xtuc/ieee754');
const xtucLong = require('@xtuc/long');

// @hapi group
const hoek = require('@hapi/hoek');
const topo = require('@hapi/topo');

// @sideway group
const sidewayAddress = require('@sideway/address');
const sidewayFormula = require('@sideway/formula');

// @sindresorhus group
const sindresorhusIs = require('@sindresorhus/is');

const app = express();
const PORT = process.env.PORT || 3000;

// ⚠️ CWE-798: Hardcoded credentials vulnerability
const DB_PASSWORD = 'admin123';
const API_SECRET = 'secret-key-12345';

// Middleware
// making change 1 to trigger the code QA scan
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
//test 11

// Routes
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Express App</title>
        <style>
          body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background-color: #f5f5f5;
          }
          .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          h1 { color: #333; }
          .endpoints {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Express Server is Running!</h1>
          <p>Welcome to your Node.js Express application.</p>
          <div class="endpoints">
            <h3>Available Endpoints:</h3>
            <ul>
              <li><strong>GET /</strong> - This home page</li>
              <li><strong>GET /api/hello</strong> - Simple API endpoint</li>
              <li><strong>POST /api/echo</strong> - Echo back JSON data</li>
            </ul>
          </div>
        </div>
      </body>
    </html>
  `);
});

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // ⚠️ CWE-89: SQL Injection vulnerability - CodeQL should detect this
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  res.send(`Query would execute: ${query}`);
});

app.post('/update-config', (req, res) => {
  const config = {};
  // ⚠️ CWE-1321: Prototype Pollution vulnerability - CodeQL should detect this
  const key = req.body.key;
  const value = req.body.value;
  config[key] = value;
  res.json({ message: 'Config updated', config });
});

app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // ⚠️ CWE-79: Reflected XSS vulnerability
  res.send(`<h1>Search Results for: ${searchTerm}</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // ⚠️ CWE-78: Command Injection vulnerability
  exec(`ping ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.send(`Error: ${error.message}`);
      return;
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// Routes using the new dependencies

// Long.js - for working with 64-bit integers
app.get('/api/long', (req, res) => {
  const longValue = Long.fromString('9223372036854775807');
  const doubled = longValue.multiply(2);
  res.json({
    original: longValue.toString(),
    doubled: doubled.toString(),
    info: 'Working with 64-bit integers using Long.js'
  });
});

// UTF8 encoding/decoding
app.post('/api/utf8', (req, res) => {
  const text = req.body.text || 'Hello 世界! 🌍';
  const encoded = utf8.encode(text);
  const decoded = utf8.decode(encoded);
  res.json({
    original: text,
    encoded: encoded,
    decoded: decoded,
    byteLength: Buffer.byteLength(encoded)
  });
});

// Glob - file pattern matching
app.get('/api/glob', async (req, res) => {
  try {
    const pattern = req.query.pattern || '*.js';
    const files = await glob(pattern, { cwd: __dirname });
    res.json({
      pattern: pattern,
      matches: files,
      count: files.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// HTTP Timer - measure HTTP request timing
app.get('/api/timer', (req, res) => {
  const request = https.get('https://api.github.com/users/github', (response) => {
    const timings = timer(response);
    
    response.on('data', () => {});
    response.on('end', () => {
      res.json({
        url: 'https://api.github.com/users/github',
        timings: {
          socket: timings.socket,
          lookup: timings.lookup,
          connect: timings.connect,
          response: timings.response,
          end: timings.end,
          total: timings.end - timings.socket
        }
      });
    });
  });
  
  request.on('error', (error) => {
    res.status(500).json({ error: error.message });
  });
});

// Address - get network addresses
app.get('/api/address', (req, res) => {
  res.json({
    ip: address.ip(),
    ipv6: address.ipv6(),
    mac: address.mac((err, addr) => {
      if (!err) return addr;
      return null;
    }),
    dns: address.dns
  });
});

// Code Frame - generate code snippets with highlighted errors
app.post('/api/codeframe', (req, res) => {
  const code = req.body.code || `function example() {
  const x = 1;
  const y = 2;
  return x + y;
}`;
  
  const location = {
    start: { line: 2, column: 8 }
  };
  
  const result = codeFrameColumns(code, location, {
    message: 'Variable declared but never used',
    highlightCode: true
  });
  
  res.json({
    code: code,
    frame: result,
    location: location
  });
});

// Vulnerable dependency usage routes

// Group 1: Utility Libraries with Prototype Pollution
app.post('/api/lodash-merge', (req, res) => {
  // ⚠️ CVE-2019-10744: Prototype Pollution in lodash < 4.17.19
  const obj = {};
  _.merge(obj, req.body);
  res.json({ merged: obj });
});

app.post('/api/minimist-parse', (req, res) => {
  // ⚠️ CVE-2020-7598: Prototype Pollution in minimist < 1.2.6
  const args = minimist(req.body.args || []);
  res.json({ parsed: args });
});

app.post('/api/dot-prop', (req, res) => {
  // ⚠️ CVE-2020-8116: Prototype Pollution in dot-prop < 5.1.1
  const obj = {};
  dotProp.set(obj, req.body.path, req.body.value);
  res.json({ result: obj });
});

// Group 2: Template Engines with XSS/RCE
app.post('/api/handlebars-render', (req, res) => {
  // ⚠️ CVE-2019-19919: Prototype Pollution in handlebars < 4.7.6
  const template = handlebars.compile(req.body.template || '<h1>{{title}}</h1>');
  const html = template({ title: req.body.title || 'Test' });
  res.send(html);
});

app.post('/api/ejs-render', (req, res) => {
  // ⚠️ CVE-2022-29078: Server-Side Template Injection in ejs < 3.1.7
  const template = req.body.template || '<h1><%= title %></h1>';
  const html = ejs.render(template, { title: req.body.title || 'Test' });
  res.send(html);
});

app.post('/api/marked-render', (req, res) => {
  // ⚠️ CVE-2022-21681: ReDoS in marked < 4.0.10
  const markdown = req.body.markdown || '# Hello World';
  const html = marked(markdown);
  res.send(html);
});

// Group 3: HTTP Libraries with various vulnerabilities
app.get('/api/axios-fetch', (req, res) => {
  // ⚠️ CVE-2021-3749: Regular Expression DoS in axios < 0.21.2
  const url = req.query.url || 'https://api.github.com/users/github';
  axios.get(url)
    .then(response => res.json({ data: response.data }))
    .catch(error => res.status(500).json({ error: error.message }));
});

app.get('/api/request-fetch', (req, res) => {
  // ⚠️ Multiple vulnerabilities in deprecated 'request' package
  const url = req.query.url || 'https://api.github.com/users/github';
  request(url, (error, response, body) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.json({ body: body });
  });
});

// Group 4: File/Archive handling with Path Traversal
app.post('/api/tar-extract', (req, res) => {
  // ⚠️ CVE-2021-37701: Arbitrary File Overwrite in tar < 6.1.9
  const tarPath = req.body.path || './archive.tar';
  res.json({ 
    message: 'Would extract tar file (disabled for safety)',
    path: tarPath,
    vulnerability: 'CVE-2021-37701'
  });
});

app.post('/api/shelljs-exec', (req, res) => {
  // ⚠️ Command Injection vulnerability with user input
  const command = req.body.command || 'echo "test"';
  res.json({
    message: 'Would execute command (disabled for safety)',
    command: command,
    warning: 'Potential command injection'
  });
});

// Group 5: Date/Validation libraries
app.get('/api/moment-parse', (req, res) => {
  // ⚠️ CVE-2022-24785: Path traversal in moment < 2.29.2
  const date = req.query.date || '2025-12-24';
  const parsed = moment(date);
  res.json({
    input: date,
    formatted: parsed.format('YYYY-MM-DD HH:mm:ss'),
    unix: parsed.unix()
  });
});

app.get('/api/validator-check', (req, res) => {
  // ⚠️ ReDoS vulnerabilities in older validator versions
  const email = req.query.email || 'test@example.com';
  res.json({
    email: email,
    isEmail: validator.isEmail(email),
    isURL: validator.isURL(email)
  });
});

// Group 6: Debug utilities
app.get('/api/debug-log', (req, res) => {
  // ⚠️ CVE-2017-16137: ReDoS in debug < 2.6.9
  const log = debug('app:server');
  log('Debug message: %s', req.query.message || 'test');
  res.json({ logged: true, message: req.query.message });
});

// @babel group vulnerabilities
app.post('/api/babel-transform', (req, res) => {
  // ⚠️ CVE-2020-5773: RCE in @babel/traverse < 7.23.2
  const code = req.body.code || 'const x = 1;';
  try {
    const ast = babelParser.parse(code);
    res.json({ 
      ast: ast,
      vulnerability: '@babel/* group - CVE-2020-5773'
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Webpack group
app.get('/api/webpack-version', (req, res) => {
  // ⚠️ Multiple vulnerabilities in webpack < 5.0.0
  res.json({
    webpackVersion: webpack.version,
    vulnerability: 'webpack group - Multiple CVEs'
  });
});

// React group
app.get('/api/react-version', (req, res) => {
  // ⚠️ CVE-2020-15168 in react-dom < 16.14.0
  res.json({
    reactVersion: React.version,
    vulnerability: 'React ecosystem vulnerabilities'
  });
});

// Crypto/Security utilities group
app.post('/api/elliptic-sign', (req, res) => {
  // ⚠️ CVE-2020-28498: Signature Malleability in elliptic < 6.5.4
  const ec = new elliptic.ec('secp256k1');
  const key = ec.genKeyPair();
  const msg = req.body.message || 'test message';
  const signature = key.sign(msg);
  res.json({
    signature: signature.toDER('hex'),
    vulnerability: 'CVE-2020-28498 - elliptic'
  });
});

app.post('/api/forge-decrypt', (req, res) => {
  // ⚠️ CVE-2022-24771, CVE-2022-24772 in node-forge < 1.3.0
  res.json({
    message: 'node-forge crypto operations',
    vulnerability: 'CVE-2022-24771, CVE-2022-24772'
  });
});

// Parser/String utilities group
app.get('/api/semver-parse', (req, res) => {
  // ⚠️ CVE-2022-25883: ReDoS in semver < 7.5.2
  const version = req.query.version || '1.2.3';
  const parsed = semver.parse(version);
  res.json({
    version: version,
    parsed: parsed,
    vulnerability: 'CVE-2022-25883 - semver'
  });
});

app.post('/api/ini-parse', (req, res) => {
  // ⚠️ CVE-2020-7788: Prototype Pollution in ini < 1.3.6
  const config = ini.parse(req.body.config || '[section]\nkey=value');
  res.json({
    parsed: config,
    vulnerability: 'CVE-2020-7788 - ini'
  });
});

app.get('/api/y18n-translate', (req, res) => {
  // ⚠️ CVE-2020-7774: Prototype Pollution in y18n < 4.0.1
  const text = req.query.text || 'Hello';
  res.json({
    text: text,
    vulnerability: 'CVE-2020-7774 - y18n'
  });
});

app.get('/api/ua-parser', (req, res) => {
  // ⚠️ CVE-2021-27292: ReDoS in ua-parser-js < 0.7.28
  const parser = new UAParser();
  const ua = req.headers['user-agent'] || 'Mozilla/5.0';
  parser.setUA(ua);
  const result = parser.getResult();
  res.json({
    userAgent: ua,
    parsed: result,
    vulnerability: 'CVE-2021-27292 - ua-parser-js'
  });
});

app.post('/api/ansi-regex', (req, res) => {
  // ⚠️ CVE-2021-3807: ReDoS in ansi-regex < 5.0.1
  const text = req.body.text || 'Hello \x1b[31mWorld\x1b[0m';
  const matches = text.match(ansiRegex());
  res.json({
    text: text,
    matches: matches,
    vulnerability: 'CVE-2021-3807 - ansi-regex'
  });
});

app.post('/api/trim', (req, res) => {
  // ⚠️ CVE-2020-7753: ReDoS in trim < 0.0.3
  const text = req.body.text || '  hello world  ';
  const trimmed = trim(text);
  res.json({
    original: text,
    trimmed: trimmed,
    vulnerability: 'CVE-2020-7753 - trim'
  });
});

app.get('/api/path-parse', (req, res) => {
  // ⚠️ CVE-2021-23343: ReDoS in path-parse < 1.0.7
  const filePath = req.query.path || '/home/user/file.txt';
  const parsed = pathParse(filePath);
  res.json({
    path: filePath,
    parsed: parsed,
    vulnerability: 'CVE-2021-23343 - path-parse'
  });
});

// Network utilities group
app.get('/api/cross-fetch', (req, res) => {
  // ⚠️ CVE-2022-1365 in cross-fetch < 3.1.5
  const url = req.query.url || 'https://api.github.com/users/github';
  crossFetch(url)
    .then(response => response.json())
    .then(data => res.json({ 
      data: data,
      vulnerability: 'CVE-2022-1365 - cross-fetch'
    }))
    .catch(error => res.status(500).json({ error: error.message }));
});

app.get('/api/websocket', (req, res) => {
  // ⚠️ CVE-2021-32640: ReDoS in ws < 7.4.6
  res.json({
    wsVersion: WebSocket.Sec,
    vulnerability: 'CVE-2021-32640 - ws'
  });
});

app.post('/api/dns-packet', (req, res) => {
  // ⚠️ CVE-2021-23386: Memory exposure in dns-packet < 5.2.2
  res.json({
    message: 'DNS packet parsing',
    vulnerability: 'CVE-2021-23386 - dns-packet'
  });
});

app.get('/api/browserslist', (req, res) => {
  // ⚠️ CVE-2021-23364: ReDoS in browserslist < 4.16.5
  const browsers = browserslist('> 0.5%, last 2 versions');
  res.json({
    browsers: browsers,
    vulnerability: 'CVE-2021-23364 - browserslist'
  });
});

// @webassemblyjs group routes
app.post('/api/wasm-parse', (req, res) => {
  // ⚠️ @webassemblyjs/* group - Multiple vulnerabilities in 1.9.0
  res.json({
    group: '@webassemblyjs',
    packages: [
      '@webassemblyjs/wasm-parser',
      '@webassemblyjs/wasm-gen',
      '@webassemblyjs/ast',
      '@webassemblyjs/helper-buffer',
      '@webassemblyjs/helper-code-frame'
    ],
    version: '1.9.0',
    vulnerability: 'Multiple CVEs in @webassemblyjs group'
  });
});

// @xtuc group routes
app.get('/api/xtuc-ieee754', (req, res) => {
  // ⚠️ @xtuc/ieee754@1.2.0
  const value = xtucIeee754.write([1.0], 0);
  res.json({
    group: '@xtuc',
    package: '@xtuc/ieee754',
    version: '1.2.0',
    result: value
  });
});

app.get('/api/xtuc-long', (req, res) => {
  // ⚠️ @xtuc/long@4.2.2
  const longVal = new xtucLong(0xFFFFFFFF, 0x7FFFFFFF);
  res.json({
    group: '@xtuc',
    package: '@xtuc/long',
    version: '4.2.2',
    value: longVal.toString()
  });
});

// @hapi group routes
app.post('/api/hapi-hoek', (req, res) => {
  // ⚠️ CVE-2020-36604: Prototype Pollution in @hapi/hoek < 9.3.1
  const obj = { a: 1 };
  const merged = hoek.merge(obj, req.body);
  res.json({
    group: '@hapi',
    package: '@hapi/hoek',
    version: '9.3.0',
    vulnerability: 'CVE-2020-36604',
    merged: merged
  });
});

app.get('/api/hapi-topo', (req, res) => {
  // ⚠️ @hapi/topo@5.1.0
  const topo = new topo.Sorter();
  topo.add('a', { after: 'b' });
  topo.add('b');
  const nodes = topo.nodes;
  res.json({
    group: '@hapi',
    package: '@hapi/topo',
    version: '5.1.0',
    nodes: nodes
  });
});

// @sideway group routes
app.post('/api/sideway-address', (req, res) => {
  // ⚠️ @sideway/address@4.1.5
  const addr = req.body.address || 'user@example.com';
  res.json({
    group: '@sideway',
    package: '@sideway/address',
    version: '4.1.5',
    address: addr
  });
});

app.post('/api/sideway-formula', (req, res) => {
  // ⚠️ @sideway/formula@3.0.1
  res.json({
    group: '@sideway',
    package: '@sideway/formula',
    version: '3.0.1',
    message: 'Formula validation'
  });
});

// @sindresorhus group routes
app.post('/api/sindresorhus-is', (req, res) => {
  // ⚠️ @sindresorhus/is@0.14.0
  const value = req.body.value;
  res.json({
    group: '@sindresorhus',
    package: '@sindresorhus/is',
    version: '0.14.0',
    checks: {
      isString: sindresorhusIs.string(value),
      isNumber: sindresorhusIs.number(value),
      isObject: sindresorhusIs.object(value)
    }
  });
});

// @types group info
app.get('/api/types-info', (req, res) => {
  res.json({
    group: '@types',
    packages: [
      '@types/node@24.10.1',
      '@types/express@4.17.0',
      '@types/lodash@4.14.165',
      '@types/glob@7.2.0',
      '@types/minimatch@5.1.2',
      '@types/babylon@6.16.9',
      '@types/babel-types@7.0.16'
    ],
    purpose: 'TypeScript type definitions'
  });
});

// @parcel/watcher group info
app.get('/api/parcel-watcher', (req, res) => {
  res.json({
    group: '@parcel/watcher',
    mainPackage: '@parcel/watcher@2.5.1',
    platformPackages: [
      '@parcel/watcher-android-arm64',
      '@parcel/watcher-darwin-arm64',
      '@parcel/watcher-darwin-x64',
      '@parcel/watcher-freebsd-x64',
      '@parcel/watcher-linux-arm-glibc',
      '@parcel/watcher-linux-arm-musl',
      '@parcel/watcher-linux-arm64-glibc',
      '@parcel/watcher-linux-arm64-musl',
      '@parcel/watcher-linux-x64-glibc',
      '@parcel/watcher-linux-x64-musl',
      '@parcel/watcher-win32-arm64',
      '@parcel/watcher-win32-ia32',
      '@parcel/watcher-win32-x64'
    ],
    version: '2.5.1',
    purpose: 'File watching across multiple platforms'
  });
});

// ⚠️ Additional Common CodeQL Vulnerabilities for Testing

// CWE-22: Path Traversal
app.get('/api/read-file', (req, res) => {
  const filename = req.query.file;
  // ⚠️ CWE-22: Improper Limitation of a Pathname to a Restricted Directory
  const filePath = path.join(__dirname, filename);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.send(data);
    }
  });
});

// CWE-94: Code Injection via eval()
app.post('/api/calculate', (req, res) => {
  const expression = req.body.expression;
  // ⚠️ CWE-94: Improper Control of Generation of Code (eval)
  const result = eval(expression);
  res.json({ expression, result });
});

// CWE-94: Code Injection via vm.runInThisContext()
app.post('/api/run-code', (req, res) => {
  const code = req.body.code;
  // ⚠️ CWE-94: Code injection via vm module
  try {
    const result = vm.runInThisContext(code);
    res.json({ code, result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CWE-502: Deserialization of Untrusted Data
app.post('/api/deserialize', (req, res) => {
  const serialized = req.body.data;
  // ⚠️ CWE-502: Dangerous deserialization with node-serialize
  try {
    const obj = serialize.unserialize(serialized);
    res.json({ deserialized: obj });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CWE-326: Inadequate Encryption Strength
app.post('/api/encrypt-weak', (req, res) => {
  const text = req.body.text;
  // ⚠️ CWE-326: Using weak encryption algorithm (DES)
  const cipher = crypto.createCipher('des', 'password123');
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted });
});

// CWE-330: Use of Insufficiently Random Values
app.get('/api/random-token', (req, res) => {
  // ⚠️ CWE-330: Using Math.random() for security-sensitive operations
  const token = Math.random().toString(36).substring(2, 15);
  res.json({ token, warning: 'Insecure random token generation' });
});

// CWE-611: Improper Restriction of XML External Entity Reference
app.post('/api/parse-xml', (req, res) => {
  const xmlData = req.body.xml;
  // ⚠️ CWE-611: XXE vulnerability - parsing XML without disabling external entities
  res.json({ 
    message: 'XML parsing (vulnerable to XXE)',
    xml: xmlData,
    warning: 'External entity processing enabled'
  });
});

// CWE-776: Unrestricted Recursive Entity References in DTDs
app.post('/api/process-dtd', (req, res) => {
  const dtd = req.body.dtd;
  // ⚠️ CWE-776: Billion Laughs attack vulnerability
  res.json({ 
    message: 'DTD processing (vulnerable to billion laughs)',
    dtd: dtd
  });
});

// CWE-918: Server-Side Request Forgery (SSRF)
app.get('/api/proxy', (req, res) => {
  const url = req.query.url;
  // ⚠️ CWE-918: SSRF vulnerability - no URL validation
  https.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  }).on('error', err => res.status(500).json({ error: err.message }));
});

// CWE-601: URL Redirection to Untrusted Site (Open Redirect)
app.get('/api/redirect', (req, res) => {
  const redirectUrl = req.query.url;
  // ⚠️ CWE-601: Open redirect vulnerability
  res.redirect(redirectUrl);
});

// CWE-184: Incomplete List of Disallowed Inputs
app.post('/api/validate-email', (req, res) => {
  const email = req.body.email;
  // ⚠️ CWE-184: Weak validation - incomplete input filtering
  const isValid = email.includes('@') && email.includes('.');
  res.json({ email, isValid, warning: 'Weak validation logic' });
});

// CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  // ⚠️ CWE-1004: Cookie without HttpOnly and Secure flags
  res.cookie('sessionId', '123456789', { 
    httpOnly: false,
    secure: false
  });
  res.json({ message: 'Logged in (insecure cookie)' });
});

// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
app.post('/api/hash-md5', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-327: Using MD5 for hashing (broken algorithm)
  const hash = crypto.createHash('md5').update(data).digest('hex');
  res.json({ data, hash, algorithm: 'MD5 (broken)' });
});

// CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
app.get('/api/session-id', (req, res) => {
  // ⚠️ CWE-338: Weak PRNG for session ID
  const sessionId = Math.floor(Math.random() * 1000000);
  res.json({ sessionId, warning: 'Weak session ID generation' });
});

// CWE-732: Incorrect Permission Assignment for Critical Resource
app.post('/api/create-file', (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;
  // ⚠️ CWE-732: File created with overly permissive permissions
  const filePath = path.join(__dirname, 'uploads', filename);
  fs.writeFile(filePath, content, { mode: 0o777 }, (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ message: 'File created with 777 permissions' });
    }
  });
});

// CWE-759: Use of a One-Way Hash without a Salt
app.post('/api/hash-password', (req, res) => {
  const password = req.body.password;
  // ⚠️ CWE-759: Hashing password without salt
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  res.json({ hash, warning: 'Password hashed without salt' });
});

// CWE-835: Loop with Unreachable Exit Condition
app.get('/api/infinite-loop', (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  // ⚠️ CWE-835: Potential infinite loop if limit is negative
  let count = 0;
  while (count < limit) {
    count += parseInt(req.query.increment) || 1;
  }
  res.json({ count });
});

// CWE-400: Uncontrolled Resource Consumption
app.post('/api/allocate-memory', (req, res) => {
  const size = req.body.size;
  // ⚠️ CWE-400: No limit on memory allocation
  const buffer = Buffer.alloc(size);
  res.json({ allocated: size, warning: 'Uncontrolled resource consumption' });
});

// CWE-1333: Regular Expression Denial of Service (ReDoS)
app.get('/api/validate-input', (req, res) => {
  const input = req.query.input;
  // ⚠️ CWE-1333: ReDoS vulnerability with catastrophic backtracking
  const regex = /^(a+)+$/;
  const isValid = regex.test(input);
  res.json({ input, isValid });
});

// CWE-134: Use of Externally-Controlled Format String
app.post('/api/format-log', (req, res) => {
  const message = req.body.message;
  // ⚠️ CWE-134: Format string vulnerability
  const formatted = require('util').format(message, req.body.args);
  res.json({ formatted });
});

// CWE-20: Improper Input Validation (Integer Overflow)
app.post('/api/add-numbers', (req, res) => {
  const a = parseInt(req.body.a);
  const b = parseInt(req.body.b);
  // ⚠️ CWE-20: No overflow check
  const sum = a + b;
  res.json({ a, b, sum });
});

// CWE-200: Exposure of Sensitive Information
app.get('/api/debug-info', (req, res) => {
  // ⚠️ CWE-200: Exposing sensitive system information
  res.json({
    env: process.env,
    platform: os.platform(),
    hostname: os.hostname(),
    userInfo: os.userInfo(),
    networkInterfaces: os.networkInterfaces()
  });
});

// CWE-209: Generation of Error Message Containing Sensitive Information
app.get('/api/database-query', (req, res) => {
  const userId = req.query.id;
  // ⚠️ CWE-209: Exposing detailed error messages
  try {
    throw new Error(`Database connection failed: user=${userId}, host=db.internal.com, password=${DB_PASSWORD}`);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CWE-319: Cleartext Transmission of Sensitive Information
app.post('/api/send-credentials', (req, res) => {
  const { username, password } = req.body;
  // ⚠️ CWE-319: Transmitting credentials in cleartext
  const credentials = `${username}:${password}`;
  res.json({ credentials, warning: 'Cleartext transmission' });
});

// CWE-598: Use of GET Request Method With Sensitive Query Strings
app.get('/api/authenticate', (req, res) => {
  const { username, password } = req.query;
  // ⚠️ CWE-598: Sensitive data in GET parameters
  res.json({ 
    message: 'Authentication attempt',
    username,
    warning: 'Password should not be in URL'
  });
});

// CWE-862: Missing Authorization
app.delete('/api/delete-user', (req, res) => {
  const userId = req.body.userId;
  // ⚠️ CWE-862: No authorization check before deletion
  res.json({ 
    message: `User ${userId} deleted`,
    warning: 'No authorization check performed'
  });
});

// CWE-863: Incorrect Authorization
app.post('/api/transfer-funds', (req, res) => {
  const { from, to, amount } = req.body;
  // ⚠️ CWE-863: No verification that requester owns 'from' account
  res.json({ 
    message: `Transferred ${amount} from ${from} to ${to}`,
    warning: 'No ownership verification'
  });
});

// CWE-918: SSRF with DNS Rebinding
app.get('/api/fetch-internal', (req, res) => {
  const hostname = req.query.host;
  // ⚠️ CWE-918: DNS rebinding vulnerability
  dns.lookup(hostname, (err, address) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ hostname, address, warning: 'DNS rebinding possible' });
    }
  });
});

// CWE-78: OS Command Injection with spawn
app.post('/api/execute', (req, res) => {
  const command = req.body.command;
  const args = req.body.args || [];
  // ⚠️ CWE-78: Command injection via spawn
  const process = spawn(command, args);
  let output = '';
  process.stdout.on('data', data => output += data);
  process.on('close', code => {
    res.json({ command, args, output, exitCode: code });
  });
});

// CWE-426: Untrusted Search Path
app.get('/api/load-module', (req, res) => {
  const moduleName = req.query.module;
  // ⚠️ CWE-426: Dynamic require with user input
  try {
    const module = require(moduleName);
    res.json({ moduleName, loaded: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CWE-780: Use of RSA Algorithm without OAEP
app.post('/api/encrypt-rsa', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-780: RSA encryption without OAEP padding
  res.json({ 
    message: 'RSA encryption without OAEP',
    data,
    warning: 'Use RSA-OAEP for encryption'
  });
});

// CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
app.post('/api/set-token', (req, res) => {
  const token = req.body.token;
  // ⚠️ CWE-614: Secure cookie not set
  res.cookie('authToken', token, {
    httpOnly: true,
    secure: false  // Should be true for HTTPS
  });
  res.json({ message: 'Token set without secure flag' });
});

// CWE-307: Improper Restriction of Excessive Authentication Attempts
app.post('/api/brute-force-login', (req, res) => {
  const { username, password } = req.body;
  // ⚠️ CWE-307: No rate limiting or account lockout
  const isValid = password === 'admin123';
  res.json({ 
    username,
    authenticated: isValid,
    warning: 'No brute force protection'
  });
});

module.exports = app;
