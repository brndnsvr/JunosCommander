#!/bin/bash

# Test Device API endpoints

echo "Testing Device API endpoints..."
echo "================================"

# Base URL
BASE_URL="http://localhost:8080/api/v1"

# First, we need to login to get a token
echo "1. Testing login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}')

echo "Login response: $LOGIN_RESPONSE"

# Extract token (if login is successful)
TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo "Failed to get auth token. Using test token for demonstration..."
  TOKEN="test-token"
fi

echo "Token: $TOKEN"
echo ""

# 2. Test creating a single device
echo "2. Testing POST /api/v1/devices (Create single device)..."
curl -X POST "$BASE_URL/devices" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "hostname": "router-test-01",
    "ip_address": "192.168.1.100",
    "site_name": "HQ",
    "device_type": "router",
    "status": "active",
    "tags": "test,production",
    "model": "MX960"
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -o /tmp/create_device_response.json

echo "Response:"
cat /tmp/create_device_response.json | python3 -m json.tool 2>/dev/null || cat /tmp/create_device_response.json
echo ""

# 3. Test listing devices
echo "3. Testing GET /api/v1/devices (List devices)..."
curl -X GET "$BASE_URL/devices" \
  -H "Authorization: Bearer $TOKEN" \
  -w "\nHTTP Status: %{http_code}\n" \
  -o /tmp/list_devices_response.json

echo "Response:"
cat /tmp/list_devices_response.json | python3 -m json.tool 2>/dev/null || cat /tmp/list_devices_response.json
echo ""

# 4. Test bulk import (CSV)
echo "4. Testing POST /api/v1/devices/bulk (Bulk import)..."
# Create a sample CSV file
cat > /tmp/test_devices.csv << EOF
hostname,ip_address,type,site,port
router-bulk-01,192.168.1.101,router,HQ,22
router-bulk-02,192.168.1.102,router,HQ,22
switch-bulk-01,192.168.1.201,switch,HQ,22
EOF

# Test multipart form upload
curl -X POST "$BASE_URL/devices/bulk" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/test_devices.csv" \
  -w "\nHTTP Status: %{http_code}\n" \
  -o /tmp/bulk_import_response.json

echo "Response:"
cat /tmp/bulk_import_response.json | python3 -m json.tool 2>/dev/null || cat /tmp/bulk_import_response.json
echo ""

echo "================================"
echo "Test complete!"