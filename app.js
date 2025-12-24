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

module.exports = app;
