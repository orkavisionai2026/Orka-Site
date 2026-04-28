/* Orka Vision V2 — Preview Server
   HTTP Range support (required for video seeking)
   + gzip compression
   + Security headers (HSTS, CSP, X-Frame-Options, etc.)
   + Cache-Control per resource type */

const http = require('http');
const fs   = require('fs');
const path = require('path');
const zlib = require('zlib');

const PORT = Number(process.env.PORT || 4173);
/* Railway/Render/etc set process.env.PORT — when present, bind to all
   interfaces. Locally (no PORT set), default to localhost for dev. */
const HOST = process.env.HOST || (process.env.PORT ? '0.0.0.0' : '127.0.0.1');
const ROOT = __dirname;

const MIME = {
  '.html' : 'text/html; charset=utf-8',
  '.css'  : 'text/css; charset=utf-8',
  '.js'   : 'application/javascript; charset=utf-8',
  '.mjs'  : 'application/javascript; charset=utf-8',
  '.json' : 'application/json; charset=utf-8',
  '.png'  : 'image/png',
  '.jpg'  : 'image/jpeg',
  '.jpeg' : 'image/jpeg',
  '.svg'  : 'image/svg+xml; charset=utf-8',
  '.webp' : 'image/webp',
  '.avif' : 'image/avif',
  '.mp4'  : 'video/mp4',
  '.mov'  : 'video/quicktime',
  '.webm' : 'video/webm',
  '.ico'  : 'image/x-icon',
  '.woff' : 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf'  : 'font/ttf',
};

// Types eligible for gzip compression
const COMPRESSIBLE = new Set([
  'text/html; charset=utf-8',
  'text/css; charset=utf-8',
  'application/javascript; charset=utf-8',
  'application/json; charset=utf-8',
  'image/svg+xml; charset=utf-8',
]);

// Cache-Control per category
function cacheControl(ext) {
  if (['.woff','.woff2','.ttf','.webp','.avif','.png','.jpg','.jpeg'].includes(ext))
    return 'public, max-age=31536000, immutable';   // 1 year — content-addressed assets
  if (['.js','.mjs','.css'].includes(ext))
    return 'public, max-age=86400';                 // 1 day
  if (['.mp4','.mov','.webm'].includes(ext))
    return 'public, max-age=86400';                 // 1 day
  if (ext === '.html')
    return 'no-store, must-revalidate';             // always fresh
  return 'public, max-age=3600';
}

// Security headers — applied to every response
const SECURITY_HEADERS = {
  // Prevents MITM / protocol downgrade (1 year, include subdomains)
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  // Prevents clickjacking
  'X-Frame-Options': 'DENY',
  // Prevents MIME-type sniffing
  'X-Content-Type-Options': 'nosniff',
  // Controls Referer information sent on navigation
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  // Restricts browser features not used by the site
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
  // CSP: tight policy for this static/Three.js site
  // - scripts: self + CDN libs (gsap, lenis) + threejs
  // - styles: self + Google Fonts
  // - fonts: self + gstatic
  // - connect: self only (no external API calls)
  // - media: self (videos)
  // - frame-ancestors: none (redundant with X-Frame-Options, belt-and-suspenders)
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "connect-src 'self'",
    "worker-src blob:",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ].join('; '),
  // Prevent IE/Edge from switching to compatibility mode
  'X-UA-Compatible': 'IE=edge',
};

http.createServer((req, res) => {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';

  // Path traversal guard
  if (urlPath.includes('..') || urlPath.includes('\0')) {
    res.writeHead(400); return res.end('bad request');
  }

  const filePath = path.join(ROOT, urlPath);
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403); return res.end('forbidden');
  }

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404); return res.end('not found');
    }

    const ext  = path.extname(filePath).toLowerCase();
    const type = MIME[ext] || 'application/octet-stream';
    const size = stat.size;
    const rangeHeader = req.headers.range;

    const baseHeaders = {
      'Content-Type'    : type,
      'Cache-Control'   : cacheControl(ext),
      'Accept-Ranges'   : 'bytes',
      'Access-Control-Allow-Origin' : '*',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      ...SECURITY_HEADERS,
    };

    // ── Range request (required for video seeking) ─────────────────────
    if (rangeHeader) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
      if (!m) {
        res.writeHead(416, { ...baseHeaders, 'Content-Range': `bytes */${size}` });
        return res.end();
      }
      const startStr = m[1], endStr = m[2];
      let start, end;
      if (startStr === '' && endStr !== '') {
        const suffix = parseInt(endStr, 10);
        start = Math.max(0, size - suffix);
        end   = size - 1;
      } else {
        start = parseInt(startStr, 10);
        end   = endStr === '' ? size - 1 : parseInt(endStr, 10);
      }
      if (isNaN(start) || isNaN(end) || start > end || end >= size) {
        res.writeHead(416, { ...baseHeaders, 'Content-Range': `bytes */${size}` });
        return res.end();
      }
      const chunkSize = end - start + 1;
      res.writeHead(206, {
        ...baseHeaders,
        'Content-Range' : `bytes ${start}-${end}/${size}`,
        'Content-Length': chunkSize,
      });
      fs.createReadStream(filePath, { start, end }).pipe(res);
      return;
    }

    // ── Gzip compression for compressible text resources ───────────────
    const acceptEncoding = req.headers['accept-encoding'] || '';
    const canGzip = COMPRESSIBLE.has(type) && acceptEncoding.includes('gzip');

    if (canGzip) {
      res.writeHead(200, {
        ...baseHeaders,
        'Content-Encoding': 'gzip',
        'Vary': 'Accept-Encoding',
        // Content-Length unknown after compression — omit it
      });
      fs.createReadStream(filePath).pipe(zlib.createGzip({ level: 6 })).pipe(res);
      return;
    }

    // ── Plain response ──────────────────────────────────────────────────
    res.writeHead(200, { ...baseHeaders, 'Content-Length': size });
    fs.createReadStream(filePath).pipe(res);
  });

}).listen(PORT, HOST, () => {
  console.log(`\nORKA V2 preview → http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log('  ✓ HTTP Range support  (video seeking)');
  console.log('  ✓ Gzip compression    (HTML/CSS/JS)');
  console.log('  ✓ Security headers    (CSP, HSTS, X-Frame-Options…)');
  console.log('  ✓ Cache-Control       (assets: 1y immutable, HTML: no-store)\n');
});
