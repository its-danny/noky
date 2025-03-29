<div align="center">
    <h1>🫢 Noky</h1>

    A lightweight, zero-knowledge API authentication proxy to verify client identity.

</div>

## Overview

**Noky** uses zero-knowledge principles and Ed25519 asymmetric cryptography to handle service-to-service authentication
so that your private credentials never travel across the network.

## How to Use

### 1. Generate Key Pair

First, generate an Ed25519 key pair using OpenSSL:

```bash
# Generate private key
openssl genpkey -algorithm Ed25519 -out private.pem

# Extract public key
openssl pkey -in private.pem -pubout -out public.pem

# Get public key in base64 format (remove headers and newlines)
openssl pkey -in public.pem -pubin -outform DER | base64
```

### 2. Configure Noky

Add your client's public key to the Noky configuration:

```toml
[services.your-service]
keys = [
    { id = "your-client-id", key = "YOUR_PUBLIC_KEY_B64" }
]
```

### 3. Sign Requests

When making requests through Noky, sign them using your private key:

```js
function sign_request(method, path, body, private_key) {
  // Generate nonce components
  session_id = generate_uuid();
  timestamp = duration_since_epoch();
  random = generate_random_string(16);
  nonce = session_id + ":" + timestamp + ":" + random;

  // Calculate body hash
  body_hash = sha256_hash(body);

  // Create message to sign: METHOD + PATH + NONCE + BODY_HASH
  message = method + path + nonce + body_hash;

  // Sign the message
  signature = ed25519_sign(message, private_key);
  signature_b64 = base64_encode(signature);

  // Return headers
  return {
    "X-Auth-Client-ID": "your-client-id",
    "X-Auth-Nonce": nonce,
    "X-Auth-Signature": signature_b64,
  };
}

// Example usage
headers = sign_request(
  (method = "POST"),
  (path = "/api/data"),
  (body = '{"key": "value"}'),
  (private_key = private_key)
);

// Make the request
response = http_post(
  (url = "http://noky:3000/api/data"),
  (headers = headers),
  (body = '{"key": "value"}')
);
```

## Example config

```toml
[services.my-service]
url = "http://localhost:8080"
routes = [
    { path = "/api/*", methods = ["GET", "POST"] },
    { path = "/public/*", methods = ["GET"], auth = false }
]
keys = [
    { id = "my-client", key = "YOUR_PUBLIC_KEY_HERE" }
]
```
