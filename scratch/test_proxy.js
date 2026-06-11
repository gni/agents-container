const http = require('http');
const net = require('net');
const url = require('url');

const server = http.createServer((req, res) => {
  console.log(`[Upstream Proxy] ${req.method} ${req.url}`);
  const parsedUrl = url.parse(req.url);
  const options = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || 80,
    path: parsedUrl.path,
    method: req.method,
    headers: req.headers
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error(`[Upstream HTTP Error] ${err.message}`);
    res.writeHead(502);
    res.end();
  });

  req.pipe(proxyReq);
});

server.on('connect', (req, clientSocket, head) => {
  console.log(`[Upstream Proxy] CONNECT ${req.url}`);
  const [host, port] = req.url.split(':');
  
  const serverSocket = net.connect(port || 443, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', (err) => {
    console.error(`[Upstream HTTPS Error] ${err.message}`);
    clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
  });

  clientSocket.on('error', () => {
    serverSocket.end();
  });
});

const PORT = 8888;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Local upstream proxy server listening on port ${PORT}...`);
});
