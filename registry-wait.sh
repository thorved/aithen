#!/bin/sh
# Wait for JWKS file to be available before starting registry

echo "Waiting for JWKS file at /certs/jwks.json..."
COUNTER=0
MAX_WAIT=60

while [ ! -f /certs/jwks.json ]; do
    if [ $COUNTER -ge $MAX_WAIT ]; then
        echo "ERROR: JWKS file not found after ${MAX_WAIT} seconds"
        exit 1
    fi
    echo "JWKS file not found, waiting... (${COUNTER}/${MAX_WAIT})"
    sleep 2
    COUNTER=$((COUNTER + 2))
done

echo "JWKS file found! Starting registry..."
ls -l /certs/jwks.json
cat /certs/jwks.json

# Start the registry with default command (Registry v3 uses /etc/distribution/config.yml)
exec registry serve /etc/distribution/config.yml
