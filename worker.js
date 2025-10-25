//
import { connect } from "cloudflare:sockets";

// How to generate a random UUID
// const userID = crypto.randomUUID();
// console.log(userID);

// Define the WebSocket ready state
const WS_READY_STATE_OPEN = 1;

// --- Helper Functions ---

/**
 * Generates a UUID from a given string using SHA-256 hashing.
 * @param {string} input - The input string to hash.
 * @returns {Promise<string>} A promise that resolves to the UUID.
 */
async function generateUUID(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  // Format the hash as a UUID
  const S = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return `${S.substring(0, 8)}-${S.substring(8, 12)}-${S.substring(12, 16)}-${S.substring(16, 20)}-${S.substring(20, 32)}`;
}

/**
 * Generates a secret path from a given string using SHA-256 hashing.
 * @param {string} input - The input string to hash.
 * @returns {Promise<string>} A promise that resolves to the secret path.
 */
async function generateSecretPath(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}


// --- Main Application Logic ---

export default {
  /**
   * Handles incoming requests.
   * @param {Request} request - The incoming request.
   * @param {object} env - The environment variables.
   * @returns {Promise<Response>} A promise that resolves to the response.
   */
  async fetch(request, env) {
    try {
      // Get configuration from environment variables
      const password = env.PASSWORD || '';
      if (!password) {
        return new Response("PASSWORD environment variable not set", { status: 400 });
      }

      const decoyUrl = env.DECOY_URL || "https://www.google.com";
      const httpIPs = (env.HTTP_IPs || 'www.visa.com,cis.visa.com').split(',');
      const httpsIPs = (env.HTTPS_IPs || 'usa.visa.com,myanmar.visa.com').split(',');
      const httpPorts = (env.HTTP_Ports || '80,8080').split(',');
      const httpsPorts = (env.HTTPS_Ports || '443,8443').split(',');

      // Generate the dynamic user ID and secret path
      const userID = await generateUUID(password);
      const secretPath = await generateSecretPath(password);

      // Get the upgrade header
      const upgradeHeader = request.headers.get("Upgrade");

      if (upgradeHeader && upgradeHeader === "websocket") {
        return await handleVlessWebSocket(request, userID);
      } else {
        const url = new URL(request.url);
        const host = request.headers.get("Host");

        switch (url.pathname) {
          case `/${secretPath}`: {
            const vlessConfig = getVlessConfig(userID, host, httpIPs, httpsIPs, httpPorts, httpsPorts);
            return new Response(vlessConfig, {
              status: 200,
              headers: { "Content-Type": "text/html;charset=utf-8" },
            });
          }
          default:
            return fetch(new Request(decoyUrl, request));
        }
      }
    } catch {
      return new Response("Bad Request", { status: 400 });
    }
  },
};


async function handleVlessWebSocket(request, userID) {
  const wsPair = new WebSocketPair();
  const [clientWS, serverWS] = Object.values(wsPair);

  serverWS.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const wsReadable = createWebSocketReadableStream(serverWS, earlyDataHeader);
  let remoteSocket = null;

  wsReadable.pipeTo(new WritableStream({
    async write(chunk) {
      if (remoteSocket) {
        const writer = remoteSocket.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const { hasError, message, addressRemote, portRemote, rawDataIndex, vlessVersion } = await parseVlessHeader(chunk, userID);
      if (hasError) {
        throw new Error(message);
      }

      const vlessRespHeader = new Uint8Array([vlessVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);

      const tcpSocket = await connect({
        hostname: addressRemote,
        port: portRemote
      });

      remoteSocket = tcpSocket;
      const writer = tcpSocket.writable.getWriter();
      await writer.write(rawClientData);
      writer.releaseLock();

      pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader);
    },
    close() {
      if (remoteSocket) {
        remoteSocket.close();
      }
    }
  })).catch(() => {
    if (remoteSocket) {
      remoteSocket.close();
    }
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWS,
  });
}

function createWebSocketReadableStream(ws, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener('message', event => controller.enqueue(event.data));
      ws.addEventListener('close', () => controller.close());
      ws.addEventListener('error', () => controller.error());
      if (earlyDataHeader) {
        try {
          const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
          controller.enqueue(Uint8Array.from(decoded, c => c.charCodeAt(0)).buffer);
        } catch {
          // Ignore errors
        }
      }
    }
  });
}

async function parseVlessHeader(buffer, userID) {
  if (buffer.byteLength < 24) {
    return { hasError: true, message: 'Invalid header length' };
  }

  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));

  const receivedUUID = formatUUID(new Uint8Array(buffer.slice(1, 17)));
  if (receivedUUID !== userID) {
    return { hasError: true, message: 'Invalid user' };
  }

  const optionsLength = view.getUint8(17);
  let offset = 18 + optionsLength;
  const command = view.getUint8(offset++);

  if (command !== 1) { // 1 = TCP
    return { hasError: true, message: 'Unsupported command, only TCP is supported' };
  }

  const port = view.getUint16(offset);
  offset += 2;

  const addressType = view.getUint8(offset++);
  let address = '';

  switch (addressType) {
    case 1: { // IPv4
      address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
      offset += 4;
      break;
    }
    case 2: { // Domain
      const domainLength = view.getUint8(offset++);
      address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
      offset += domainLength;
      break;
    }
    case 3: { // IPv6
      const ipv6 = Array.from(new Uint16Array(buffer.slice(offset, offset + 16)))
        .map(h => h.toString(16).padStart(4, '0')).join(':');
      address = `[${ipv6}]`;
      offset += 16;
      break;
    }
    default:
      return { hasError: true, message: 'Unsupported address type' };
  }

  return {
    hasError: false,
    addressRemote: address,
    portRemote: port,
    rawDataIndex: offset,
    vlessVersion: version,
  };
}

function pipeRemoteToWebSocket(remoteSocket, ws, vlessHeader) {
  remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (ws.readyState === WS_READY_STATE_OPEN) {
        if (vlessHeader) {
          const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
          combined.set(vlessHeader, 0);
          combined.set(new Uint8Array(chunk), vlessHeader.byteLength);
          ws.send(combined.buffer);
          vlessHeader = null;
        } else {
          ws.send(chunk);
        }
      }
    },
    close() {
      ws.close();
    },
    abort() {
      ws.close(1011, "Remote socket aborted");
    }
  })).catch(() => {});
}

function formatUUID(bytes) {
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
}

function getVlessConfig(userID, hostName, httpIPs, httpsIPs, httpPorts, httpsPorts) {
  const randomHttpIP = httpIPs[Math.floor(Math.random() * httpIPs.length)];
  const randomHttpsIP = httpsIPs[Math.floor(Math.random() * httpsIPs.length)];
  const randomHttpPort = httpPorts[Math.floor(Math.random() * httpPorts.length)];
  const randomHttpsPort = httpsPorts[Math.floor(Math.random() * httpsPorts.length)];

  const vlessWs = `vless://${userID}@${randomHttpIP}:${randomHttpPort}?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}-HTTP`;
  const vlessWsTls = `vless://${userID}@${randomHttpsIP}:${randomHttpsPort}?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}-HTTPS`;

  const allConfigs = [vlessWs, vlessWsTls].join('\n');
  const b64Configs = btoa(allConfigs);

  return `
    <html>
      <head>
        <title>VLESS Configuration</title>
      </head>
      <body>
        <h1>VLESS Configuration</h1>
        <p>Your User ID is: <strong>${userID}</strong></p>

        <h2>Subscription URL</h2>
        <p><code>https://${hostName}/${b64Configs}</code></p>

        <h2>Individual Links</h2>
        <h3>WebSocket (No TLS)</h3>
        <p><code>${vlessWs}</code></p>
        <h3>WebSocket (TLS)</h3>
        <p><code>${vlessWsTls}</code></p>
      </body>
    </html>
  `;
}