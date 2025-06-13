// deploy.js
import http from 'http';
import { exec } from 'child_process';
import crypto from 'crypto';
import path from 'path';
import dotenv from 'dotenv';

// 1) Load .env.local from the project root
dotenv.config({ path: path.resolve(process.cwd(), '.env.local') });

const SECRET = process.env.WEBHOOK_SECRET;
const PORT   = process.env.PORT || 7777;

if (!SECRET) {
  console.error('❌ WEBHOOK_SECRET is not set in .env.local. Exiting.');
  process.exit(1);
}

function verifySignature(req, rawBody) {
  const sigHeader = req.headers['x-hub-signature-256'];
  if (!sigHeader) return false;

  const [algo, hash] = sigHeader.split('=');
  if (algo !== 'sha256') return false;

  const hmac = crypto.createHmac('sha256', SECRET);
  const digest = hmac.update(rawBody).digest('hex');
  return digest === hash;
}

http
  .createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/webhook') {
      res.writeHead(404);
      return res.end();
    }

    // 2) Accumulate raw Buffer chunks
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);

      // 3) Verify HMAC signature
      if (!verifySignature(req, rawBody)) {
        console.error('⚠️ Invalid signature, rejecting.');
        res.writeHead(401);
        return res.end('Invalid signature\n');
      }

      // OK to deploy
      console.log('✅ Webhook verified, deploying…');
      res.writeHead(200);
      res.end('Deploy triggered\n');

      exec(
        `
        cd /home/refusionist/refusion-core/client/refusionist.com &&
        git pull &&
        npm install &&
        npm run build &&
        pm2 restart refusionist
        `,
        (err, stdout, stderr) => {
          if (err) console.error(`❌ Error: ${err.message}`);
          if (stdout) console.log(stdout);
          if (stderr) console.error(stderr);
        }
      );
    });
  })
  .listen(PORT, () => {
    console.log(`🚀 Webhook server listening on port ${PORT}`);
  });
