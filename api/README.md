# API Documentation

This document describes the HTTP API endpoints provided by the Vocdoni Z-Sandbox service.

## Endpoints

### Health Check

#### GET /ping
Simple health check endpoint to verify the API server is running.

**Response**: Empty response with HTTP 200 OK status

### Process Management

#### POST /process
Creates a new voting process setup and returns it.

**Request Body**:
```json
{
  "censusRoot": "bytes",
  "ballotMode": {
    "maxCount": "number",
    "maxValue": "bigint",
    "minValue": "bigint",
    "forceUniqueness": "boolean",
    "costFromWeight": "boolean",
    "costExponent": "number",
    "maxTotalCost": "bigint",
    "minTotalCost": "bigint"
  },
  "nonce": "number",
  "chainID": "number",
  "signature": "bytes"
}
```

**Response Body**:
```json
{
  "processID": "bytes",
  "encryptionPubKey": ["bigint", "bigint"],
  "stateRoot": "bytes"
}
```

#### GET /process
Gets information about a voting process.

**Response Body**: Process information (format depends on process state)

### Census Management

#### POST /census
Creates a new census.

**Response Body**:
```json
{
  "census": "uuid"
}
```

#### POST /census/participants
Adds participants to an existing census.

**URL Parameters**:
- id: Census UUID

**Request Body**:
```json
{
  "participants": [
    {
      "key": "bytes",
      "weight": "bigint" // optional
    }
  ]
}
```

**Response**: Empty response with HTTP 200 OK status

#### GET /census/participants
Gets the list of participants in a census.

**URL Parameters**:
- id: Census UUID

**Response Body**:
```json
{
  "participants": [
    {
      "key": "bytes",
      "weight": "bigint"
    }
  ]
}
```

#### GET /census/root
Gets the Merkle root of a census.

**URL Parameters**:
- id: Census UUID

**Response Body**:
```json
{
  "root": "bytes"
}
```

#### GET /census/size
Gets the number of participants in a census.

**URL Parameters**:
- id: Census UUID

**Response Body**:
```json
{
  "size": "number"
}
```

#### DELETE /census
Deletes a census.

**URL Parameters**:
- id: Census UUID

**Response**: Empty response with HTTP 200 OK status

#### GET /census/proof
Gets a Merkle proof for a participant in a census.

**URL Parameters**:
- id: Census UUID
- key: Participant key (hex encoded)

**Response Body**:
```json
{
  "siblings": "bytes"
}
```

## Error Responses

All endpoints may return error responses with the following format:

```json
{
  "error": "string"
}
```

Common HTTP status codes:
- 200: Success
- 400: Bad Request
- 404: Not Found
- 500: Internal Server Error

