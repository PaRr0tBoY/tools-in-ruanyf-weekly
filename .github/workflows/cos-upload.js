#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

// 解析命令行参数
const args = {};
process.argv.slice(2).forEach((v, i, a) => {
  if (v.startsWith('--')) args[v.slice(2)] = a[i + 1];
});

const secretId = args['secret-id'];
const secretKey = args['secret-key'];
const token = args['token'];
const bucket = args['bucket'];
const region = args['region'];
const cosKey = args['cos-key'];
const file = args['file'];
const contentType = args['content-type'];
const startTime = parseInt(args['start-time']);
const expiredTime = parseInt(args['expired-time']);

if (!secretId || !secretKey || !token || !bucket || !region || !cosKey || !file || !contentType) {
  console.error('Missing required arguments');
  process.exit(1);
}

const fileBuffer = fs.readFileSync(file);
const fileSize = fileBuffer.length;

// 构建 Authorization
const keyTime = startTime + ';' + expiredTime;
const signKey = crypto.createHmac('sha1', secretKey).update(keyTime).digest('hex');

const headerKeys = ['host', 'content-length'].sort();
const httpHeaders = headerKeys.map(k =>
  k.toLowerCase() + '=' + (k === 'host'
    ? encodeURIComponent(bucket + '.cos.' + region + '.myqcloud.com')
    : fileSize)
).join('&');
const httpString = 'PUT\n/' + cosKey + '\n\n' + httpHeaders + '\n';
const stringToSign = 'sha1\n' + keyTime + '\n' + crypto.createHash('sha1').update(httpString).digest('hex') + '\n';
const signature = crypto.createHmac('sha1', signKey).update(stringToSign).digest('hex');

const authorization = 'q-sign-algorithm=sha1&q-ak=' + secretId +
  '&q-sign-time=' + keyTime + '&q-key-time=' + keyTime +
  '&q-header-list=' + headerKeys.join(';') + '&q-url-param-list=&q-signature=' + signature;

const url = 'https://' + bucket + '.cos.' + region + '.myqcloud.com/' + cosKey;

const req = https.request(url, {
  method: 'PUT',
  headers: {
    'Authorization': authorization,
    'Content-Length': fileSize,
    'Content-Type': contentType,
    'x-cos-security-token': token,
    'Host': bucket + '.cos.' + region + '.myqcloud.com'
  }
}, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      console.log(JSON.stringify({ success: true, statusCode: res.statusCode }));
    } else {
      console.error('Upload failed: ' + data);
      process.exit(1);
    }
  });
});

req.on('error', (e) => { console.error(e); process.exit(1); });
req.write(fileBuffer);
req.end();
