# Secure Network Tunnel with mutual TLS (mTLS)

A minimal, secure TCP tunnel written in C using OpenSSL, implementing mutual TLS (mTLS) for Zero Trust networking.


## Features

- Full TCP forwarding over TLS 1.2/1.3
- Mutual authentication (both client and server must present valid X.509 certificates)
- No application changes required — works as a transparent proxy
- Written in pure C with no external dependencies (except OpenSSL)
- Graceful connection handling with select()-based I/O
- Memory-safe (no leaks — verified with Valgrind)

## Quick Start

1. Generate certificates:
   ./scripts/gen-certs.sh

2. Build the project:
   make

3. Run a target service (e.g., netcat):
   nc -l 5432

4. Start the tunnel server:
   ./tunnel-server

5. Start the tunnel client:
   ./tunnel-client

6. Connect your app to localhost:8080:
   echo "Hello" | nc localhost 8080

→ You should see "Hello" appear in the nc -l 5432 terminal.

## Architecture

[Application] → localhost:8080
                ↓
          [tunnel-client]
                ↓ (mTLS over port 8443)
          [tunnel-server]
                ↓
        [Target Service: 127.0.0.1:5432]
 
## Security

- Encryption: TLS 1.3 (AES-GCM / ChaCha20)
- Authentication: Both sides verify certificates signed by a private CA
- Zero Trust: Every connection requires a valid certificate
- No secrets in source code
- Uses SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT

> WARNING: Never commit .key files! They are excluded via .gitignore.

## Project Structure

.
├── src/
│   ├── tls-server.c    # tunnel server
│   └── tls-client.c    # tunnel client
├── scripts/
│   └── gen-certs.sh    # certificate generator
├── Makefile
├── README.md
└── .gitignore

## Use Cases  
                    
- Secure database access (PostgreSQL, MySQL)
- mTLS between microservices
- Add encryption to legacy apps
- Secure internal tunnels without public exposure

## Testing  

Terminal 1: nc -l 5432   
Terminal 2: ./tunnel-server  
Terminal 3: ./tunnel-client     
Terminal 4: echo "test" | nc localhost 8080  

Result: "test" appears in Terminal 1.

To test mTLS enforcement: 
  openssl s_client -connect localhost:8443 -CAfile ca.pem
  → Should FAIL ("certificate required")

  openssl s_client -connect localhost:8443 -CAfile ca.pem -cert client.pem -key client.key
  → Should SUCCEED

## Customizaton

Edit these in source files:

In tls-server.c:
  #define TARGET_PORT 5432

In tls-client.c:
  #define LOCAL_LISTEN_PORT 8080

Then rebuild: 
  make clean && make
        
## License

For educational and demonstration purposes only.  
