# Matter Sample in Typescript

This project is a TypeScript implementation that includes functions for generating cryptographic verifiers, manual pairing codes, and other Matter-related utilities.

## Functions

### `generateVerifier`

Generates a cryptographic verifier using a passcode and salt and iteration count.

#### Parameters:
- `passcode: number`: The passcode used for generating the verifier.
- `salt: Buffer`: The salt value as a buffer.
- `iterations: number`: (Optional) Number of iterations (default 1000).

#### Returns:
- `string`: Base64 encoded verifier value.

### `generateManualPairingCode`

Generates a manual pairing code using a discriminator, pincode, vendor ID, and product ID.

#### Parameters:
- `discriminator: number`: The discriminator value.
- `pincode: number`: The pincode used for generating the pairing code.
- `vid: number`: The vendor ID.
- `pid: number`: The product ID.

#### Returns:
- `string`: Manual pairing code.

### `generatePasscode`

Generates a random passcode.

#### Returns:
- `number`: A randomly generated passcode.

### `generateSalt`

Generates a random salt.

#### Returns:
- `string`: A randomly generated salt as a base64 encoded string.

### `generateDiscriminator`

Generates a random discriminator.

#### Returns:
- `number`: A randomly generated discriminator.

## Usage Example

Here's how you can use the functions in this project:

```typescript
import {
    generateDiscriminator,
    generateManualPairingCode,
    generatePasscode,
    generateSalt,
    generateVerifier
} from "./matter";

const passcode: number = generatePasscode();
const salt: string = generateSalt();
const discriminator: number = generateDiscriminator();
const vendorId: number = 12340;
const productId: number = 56780;

const verifier = generateVerifier(passcode, Buffer.from(salt));
console.log(`Verifier: ${verifier.toString('base64')}`);

const manualPairingCode = generateManualPairingCode(discriminator, passcode, vendorId, productId);
console.log(`ManualPairingCode: ${manualPairingCode}`);
