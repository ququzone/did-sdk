DID SDK
=======

## Example

### DID document

```
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/secp256k1-2019/v1"
  ],
  "id": "did:io:0x8d38efE45794D7FCeeA10b2262C23C12245959dB",
  "verificationMethod": [
    {
      "id": "did:io:0x8d38efE45794D7FCeeA10b2262C23C12245959dB#key-0",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:io:0x8d38efE45794D7FCeeA10b2262C23C12245959dB",
      "publicKeyBase58": "kH5zYb8DewE5u5QMLNm7hXC3kzSKy9rev5vocBMw4pUE"
    }
  ],
  "authentication": [
    "did:io:0x8d38efE45794D7FCeeA10b2262C23C12245959dB#key-0"
  ],
  "assertionMethod": [
    "did:io:0x8d38efE45794D7FCeeA10b2262C23C12245959dB#key-0"
  ]
}
```

### Verifiable Credential

```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/w3bstream/v1"
  ],
  "id": "urn:uuid:74ba8f58-58ac-4fc7-b702-1788783933c8",
  "type": [
    "VerifiableCredential",
    "https://www.w3.org/2018/credentials/w3bstream/v1"
  ],
  "issuer": "did:io:0xB9734E8a40C93fD90C64Ebc599be6246f97a5595",
  "issuanceDate": "2022-11-13T21:24:41Z",
  "credentialSubject": {
    "id": "did:id:0x8d38efE45794D7FCeeA10b2262C23C12245959dB",
    "readStreamData": "allow"
  },
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2022-11-13T21:24:41Z",
    "verificationMethod": "did:io:0xB9734E8a40C93fD90C64Ebc599be6246f97a5595#key-0",
    "proofPurpose": "assertionMethod",
    "proofValue": "KDvYa5ZtH1G8LQk55gAEC3jcAxaKVCDti2JEZGW7czf43cE7S4TSSE4unHcvV5RJ5MRMv2TUab9i7fy9SMSUXCtEj"
  }
}
```

### Verifiable Presentation

```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "urn:uuid:324f4df0-cf19-42fa-b17a-538fd5a22fb3",
  "holder": "did:io:0xF765EA2911d83a0534a971C6E684d389C26C6a92",
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/w3bstream/v1"
      ],
      "id": "urn:uuid:c8b43008-69ac-459d-8ca6-49e1777c7319",
      "type": [
        "VerifiableCredential",
        "https://www.w3.org/2018/credentials/w3bstream/v1"
      ],
      "issuer": "did:io:0xa3CFa8B974eCD637f2231Cf765F88A84d3b09651",
      "issuanceDate": "2022-11-13T21:24:41Z",
      "credentialSubject": {
        "id": "did:io:0xF765EA2911d83a0534a971C6E684d389C26C6a92",
        "readStreamData": "allow"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2022-11-13T21:24:41Z",
        "verificationMethod": "did:io:0xa3CFa8B974eCD637f2231Cf765F88A84d3b09651#key-0",
        "proofPurpose": "assertionMethod",
        "proofValue": "DhKgyXhTdke3NdkQb7pDvKHmTU5Y238sC6roLNyoYfL4ApWKkJkah1pNWA87QjnfaLby5RZDZWdC9SskqGybMXVFv"
      }
    }
  ],
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2022-11-13T21:24:41Z",
    "verificationMethod": "did:io:0xF765EA2911d83a0534a971C6E684d389C26C6a92#key-0",
    "proofPurpose": "assertionMethod",
    "proofValue": "5RXdkHMAaxhPVSk5LTi9JT6bPBnDDS8bfBvSqR82dzA6CRqiSHHtu13iXgU1AqB1H2dJFyy7breboBB8mYxyESSGY"
  }
}
```
