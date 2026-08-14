#!/usr/bin/env bash

# This file is sourced by migration and smoke-test scripts.

load_generator_service_secret() {
  local namespace=$1 secret_name=$2
  GENERATOR_SERVICE_SECRET=$(kubectl get secret "$secret_name" -n "$namespace" -o jsonpath='{.data.GENERATOR_SERVICE_SECRET}' | base64 --decode)
  export GENERATOR_SERVICE_SECRET
}

create_generator_token() {
  local scope=$1
  GENERATOR_SCOPE=$scope python3 - <<'PY'
import base64
import hashlib
import hmac
import json
import os
import time

def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

now = int(time.time())
header = encode({"alg": "HS256", "typ": "JWT"})
payload = encode({
    "iss": "jcode-backend",
    "aud": "jcode-generator",
    "sub": "jcode-backend",
    "iat": now,
    "exp": now + 60,
    "scope": os.environ["GENERATOR_SCOPE"],
    "namespace_prefix": "jcode-",
})
unsigned = f"{header}.{payload}"
signature = hmac.new(
    os.environ["GENERATOR_SERVICE_SECRET"].encode(),
    unsigned.encode(),
    hashlib.sha256,
).digest()
print(f"{unsigned}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}")
PY
}
