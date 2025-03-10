# Matter Sample in Typescript

This project is a TypeScript implementation that includes functions for generating cryptographic verifiers and manual pairing codes.

## Functions

### `generateVerifier`

Generates a cryptographic verifier using a passcode, salt, and iteration count.

#### Parameters:
- `passcode: number`: The passcode used for generating the verifier.
- `salt: Buffer`: The salt value as a buffer.
- `iterations: number`: The number of iterations for the PBKDF2 function.

#### Returns:
- `string`: A base64 encoded verifier.

### `generateManualPairingCode`

Generates a manual pairing code using a discriminator, pincode, vendor ID, and product ID.

#### Parameters:
- `discriminator: number`: The discriminator value.
- `pincode: number`: The pincode used for generating the pairing code.
- `vid: number`: The vendor ID.
- `pid: number`: The product ID.

#### Returns:
- `string`: Manual pairing code.

## Usage Example

Here's how you can use the functions in this project:

```typescript
const passcode: number = 11223344;
const salt: string = 'sample_salt_bytes';
const iterations: number = 1122;
const discriminator: number = 3840;

const verifier = generateVerifier(passcode, Buffer.from(salt), iterations);
console.log(`Verifier: ${verifier}`);

const manualPairingCode = generateManualPairingCode(discriminator, passcode, 12340, 56780);
console.log(`ManualPairingCode: ${manualPairingCode}`);
