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

console.log("Inputs:");
console.log(`Passcode: ${passcode}`);
console.log(`Salt: ${salt}`);
console.log(`Discriminator: ${discriminator}`);
console.log(`Vendor ID: ${vendorId}`);
console.log(`Product ID: ${productId}`);
console.log("-------------------");

const verifier = generateVerifier(passcode, Buffer.from(salt));
const manualPairingCode = generateManualPairingCode(discriminator, passcode, vendorId, productId);

console.log("Outputs:");
console.log(`Verifier: ${verifier}`);
console.log(`ManualPairingCode: ${manualPairingCode}`);
