import {generateManualPairingCode, generateVerifier} from "./matter";

const passcode: number = 11223344;
const salt: string = 'sample_salt_bytes';
const iterations: number = 1122;
const discriminator: number = 3840;

const verifier = generateVerifier(passcode, Buffer.from(salt), iterations);
console.log(`Verifier: ${verifier}`);

const manualPairingCode = generateManualPairingCode(discriminator, passcode, 12340, 56780);
console.log(`ManualPairingCode: ${manualPairingCode}`);
