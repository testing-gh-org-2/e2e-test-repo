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

module.exports = app;
