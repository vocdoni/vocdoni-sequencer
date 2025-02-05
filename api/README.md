# API Documentation

This document describes the HTTP API endpoints.

## Endpoints

### Health Check

#### GET /ping
Example: `GET /ping`
Simple health check endpoint to verify the API server is running.

**Response**: Empty response with HTTP 200 OK status

### Process Management

#### POST /process
Example: `POST /process`
Creates a new voting process setup and returns it. The process is not stored.

**Request Body**:
```json
{
  "censusRoot": "hexBytes",
  "ballotMode": {
    "maxCount": "number",
    "maxValue": "bigintStr",
    "minValue": "bigintStr",
    "forceUniqueness": "boolean",
    "costFromWeight": "boolean",
    "costExponent": "number",
    "maxTotalCost": "bigintStr",
    "minTotalCost": "bigintStr"
  },
  "nonce": "number",
  "chainID": "number",
  "signature": "bytes"
}
```

**Response Body**:
```json
{
  "processID": "hexBytes",
  "encryptionPubKey": ["bigintStr", "bigintStr"],
  "stateRoot": "hexBytes"
}
```

#### GET /process?id=000005390056d6ed515b2e0af39bb068f587d0de83facd1b0000000000000003
Gets information about an existing voting process. It must exist in the smart contract.

**Response Body**:
```json
{
  "id": "hexBytes",
  "status": "number",
  "organizationId": "address",
  "encryptionKey": {
    "x": "bigintStr",
    "y": "bigintStr"
  },
  "stateRoot": "hexBytes",
  "result": ["bigintStr"],
  "startTime": "timestamp",
  "duration": "duration",
  "metadataURI": "string",
  "ballotMode": {
    "maxCount": "number",
    "maxValue": "bigintStr",
    "minValue": "bigintStr",
    "forceUniqueness": "boolean",
    "costFromWeight": "boolean",
    "costExponent": "number",
    "maxTotalCost": "bigintStr",
    "minTotalCost": "bigintStr"
  },
  "census": {
    "censusOrigin": "number",
    "maxVotes": "bigintStr",
    "censusRoot": "hexBytes",
    "censusURI": "string"
  },
  "metadata": {
    "title": {
      "languageCode": "string"
    },
    "description": {
      "languageCode": "string"
    },
    "media": {
      "header": "string",
      "logo": "string"
    },
    "questions": [
      {
        "title": {
          "languageCode": "string"
        },
        "description": {
          "languageCode": "string"
        },
        "choices": [
          {
            "title": {
              "languageCode": "string"
            },
            "value": "number",
            "meta": {
              "key": "string"
            }
          }
        ],
        "meta": {
          "key": "string"
        }
      }
    ],
    "processType": {
      "name": "string",
      "properties": {
        "key": "string"
      }
    }
  }
}
```

### Census Management

#### POST /census
Example: `POST /census`
Creates a new census.

**Response Body**:
```json
{
  "census": "uuid"
}
```

#### POST /census/participants?id=5fac16ce-3555-41a1-9ad9-a9176e8d08be
Adds participants to an existing census.

**URL Parameters**:
- id: Census UUID

**Request Body**:
```json
{
  "participants": [
    {
      "key": "hexBytes", // if more than 20 bytes, it is hashed and trunkated
      "weight": "bigintStr" // optional
    }
  ]
}
```

**Response**: Empty response with HTTP 200 OK status

#### GET /census/participants?id=5fac16ce-3555-41a1-9ad9-a9176e8d08be
Gets the list of participants in a census.

**URL Parameters**:
- id: Census UUID

**Response Body**:
```json
{
  "participants": [
    {
      "key": "hexBytes",
      "weight": "bigintStr"
    }
  ]
}
```

#### GET /census/root?id=5fac16ce-3555-41a1-9ad9-a9176e8d08be
Gets the Merkle root of a census.

**URL Parameters**:
- id: Census UUID

**Response Body**:
```json
{
  "root": "hexBytes"
}
```

#### GET /census/size?id=5fac16ce-3555-41a1-9ad9-a9176e8d08be
Gets the number of participants in a census.

**URL Parameters**:
- id: Census UUID

**Response Body**:
```json
{
  "size": "number"
}
```

#### DELETE /census?id=5fac16ce-3555-41a1-9ad9-a9176e8d08be
Deletes a census.

**URL Parameters**:
- id: Census UUID

**Response**: Empty response with HTTP 200 OK status

#### GET /census/proof?root=bb7f7eef18b85b131...&key=4179e431856a710bd...
Gets a Merkle proof for a participant in a census.

**URL Parameters**:
- root: Census merkle root (hex encoded)
- key: Participant key (hex encoded)

**Response Body**:
```json
{
  "root": "hexBytes",
  "key": "hexBytes",
  "value": "hexBytes",
  "siblings": "hexBytes",
  "weight": "bigintStr" // the value transformed to bigInt
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
