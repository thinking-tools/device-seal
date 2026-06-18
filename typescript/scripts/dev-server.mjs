// Minimal zero-dependency static server for the local example, so `npm run dev` needs nothing beyond
// Node (the package itself has no runtime deps, and we keep it that way). Serves the package directory
// over http://localhost — a secure context, so WebAuthn and crypto.subtle work — and opens the example.
//
//   npm run dev            build, serve, open the example
//   PORT=8123 npm run dev  choose the port (default 8080)
//   NO_OPEN=1 npm run dev  serve without launching a browser

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

// The package root is the parent of this scripts/ directory; resolved from the file URL so it is
// independent of the current working directory.
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const port = Number(process.env.PORT) || 8080;
const openPath = '/example/';

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  // ES module imports require a JavaScript MIME type, or the browser refuses to execute them.
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.ts': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host}`);
    let pathname = decodeURIComponent(url.pathname);
    if (pathname === '/') {
      response.writeHead(302, { location: openPath }).end();
      return;
    }
    if (pathname.endsWith('/')) pathname += 'index.html';

    // Resolve under the root and reject anything that escapes it (path traversal).
    const filePath = normalize(join(root, pathname));
    if (filePath !== root && !filePath.startsWith(root + sep)) {
      response.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }).end('403 Forbidden');
      return;
    }

    const fileInfo = await stat(filePath).catch(() => null);
    if (!fileInfo?.isFile()) {
      response
        .writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
        .end(`404 Not Found: ${pathname}`);
      return;
    }

    response.writeHead(200, {
      'content-type': CONTENT_TYPES[extname(filePath)] ?? 'application/octet-stream',
      'cache-control': 'no-cache',
    });
    response.end(await readFile(filePath));
  } catch (error) {
    response
      .writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
      .end(`500 ${error instanceof Error ? error.message : String(error)}`);
  }
});

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${port} is already in use. Pick another, e.g. PORT=8123 npm run dev`);
    process.exit(1);
  }
  throw error;
});

server.listen(port, () => {
  const url = `http://localhost:${port}${openPath}`;
  console.log(`device-seal example → ${url}`);
  console.log(`serving ${root} (Ctrl-C to stop)`);
  if (process.env.NO_OPEN) return;
  // Best effort: a failure to launch a browser is never fatal — the URL is printed above.
  const [command, ...prefixArgs] =
    process.platform === 'darwin'
      ? ['open']
      : process.platform === 'win32'
        ? ['cmd', '/c', 'start', '']
        : ['xdg-open'];
  try {
    spawn(command, [...prefixArgs, url], { stdio: 'ignore', detached: true }).unref();
  } catch {
    /* opening the browser is optional */
  }
});
