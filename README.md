## Secure Network Tunnel with mutual TLS (mTLS)

A minimal, secure TCP tunnel written in C using OpenSSL, implementing mutual TLS (mTLS) for Zero Trust networking.

## Features

- Full TCP forwarding over TLS 1.2/1.3
- Mutual authentication (both client and server must present valid X.509 certificates)
- No application changes required — works as a transparent proxy
- Written in pure C with no external dependencies (except OpenSSL)

Build the project: make

Run a target service (e.g., netcat): nc -l 5432

Start the tunnel server: ./tunnel-server
Start the tunnel client: ./tunnel-client
Connect your app to localhost:8080: echo "Hello" | nc localhost 8080

You should see "Hello" appear in the nc -l 5432 terminal.



## Architecture

[Application ] -> localhost:8080 -> [tunnel-client] - (mTLS over port 8443) - [tunnel-server] -> [Target Service: 127.0.0.1:5432]



## Security
Encryption: TLS 1.3 (AES-GCM / ChaCha20)
Authentication: Both sides verify certificates signed by a private CA
Zero Trust: Every connection requires a valid certificate
No secrets in source code
Uses SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
Socket-level timeouts prevent Slowloris-style DoS attacks
Certificate verification callback for extensibility

## WARNING: Never commit .key files!!! They are excluded via .gitignore.

## Use Cases
Secure database access (PostgreSQL, MySQL)
mTLS between microservices
Add encryption to legacy apps without code changes
Secure internal tunnels without public exposure
Educational tool for learning TLS, sockets, and C systems programming

## Testing
Basic functionality

# Terminal 1
nc -l 5432

# Terminal 2
./tunnel-server

# Terminal 3
./tunnel-client

# Terminal 4

Result: "test" appears in Terminal 1.

## mTLS enforcement test
# Should FAIL ("certificate required")
openssl s_client -connect localhost:8443 -CAfile ca.pem

# Should SUCCEED
openssl s_client -connect localhost:8443 -CAfile ca.pem -cert client.pem -key client.key

## Timeout test

nc localhost 8443  # wait 30+ seconds -> connection closes automatically
Customization
Edit these in source files:

In src/tls-server.c:
#define TARGET_PORT 5432
In src/tls-client.c:
#define LOCAL_LISTEN_PORT 8080

Then rebuild:
Future versions may support CLI arguments (--port, --host) for greater flexibility.

## Known Limitations!
This is an educational project. In production environments, consider:

Adding hostname/IP verification in certificates (via X509_VERIFY_PARAM)
Implementing full resource cleanup with goto cleanup pattern
Replacing hardcoded values with command-line arguments
Using non-blocking I/O or threading for high concurrency
Large data transfers (>500 KB) may be truncated if the client closes the connection before all data is forwarded (due to TCP half-close behavior)

## License
For educational and demonstration purposes only.
Not intended for production use without further security hardening.
