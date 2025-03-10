import { pbkdf2Sync } from 'crypto';
import * as elliptic from 'elliptic';
import BN from 'bn.js';

const ec = new elliptic.ec('p256');

function generateVerifier(passcode: number, salt: Buffer, iterations: number): string {
    const WS_LENGTH: number = 32 + 8; // Equivalent to NIST256p.baselen + 8
    const passcodeBuffer: Buffer = Buffer.alloc(4);
    passcodeBuffer.writeUInt32LE(passcode, 0);

    const ws: Buffer = pbkdf2Sync(passcodeBuffer, salt, iterations, WS_LENGTH * 2, 'sha256');
    const w0Bytes: Buffer = ws.subarray(0, WS_LENGTH);
    const w1Bytes: Buffer = ws.subarray(WS_LENGTH);

    const order: BN = ec.curve.n as BN;
    const w0: BN = new BN(w0Bytes).umod(order);
    const w1: BN = new BN(w1Bytes).umod(order);

    const L: elliptic.curve.base.BasePoint = ec.g.mul(w1);

    const w0Array: number[] = w0.toArray('be', 32);
    const LArray: number[] = L.encode('array', false) as number[];

    return Buffer.concat([Buffer.from(w0Array), Buffer.from(LArray)]).toString('base64');
}

function generateManualPairingCode(discriminator: number, pincode: number, vid: number, pid: number): string {
    const shortDiscriminator = discriminator >> 8;

    // Chunk 1 (4 bits)  : <Version 1Bit><VidPidPresent 1Bit><ShortDiscriminator First2Bits>
    // Chunk 2 (16 bits) : <ShortDiscriminator last2Bits><Pincode Last14Bits>
    // Chunk 3 (16 bits) : <Pincode First13Bits>

    const chunk1 = (0 << 3 | 1 << 2 | shortDiscriminator >> 2).toString().padStart(1, '0');
    const chunk2 = (((shortDiscriminator & 0x03) << 14) | pincode & 0x3FFF).toString().padStart(5, '0');
    const chunk3 = (pincode >> 14).toString().padStart(4, '0');
    const chunk4 = vid.toString().padStart(5, '0');
    const chunk5 = pid.toString().padStart(5, '0');

    const payload = `${chunk1}${chunk2}${chunk3}${chunk4}${chunk5}`;
    return `${payload}${Verhoeff.calcCheckDigit(payload)}`;
}

class Verhoeff {
    private static d: number[][] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ];

    private static p: number[][] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ];

    private static inv: number[] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

    static calcCheckDigit(num: string): string {
        let c = 0;
        const numReverse = num.split('').reverse();
        for (let i = 0; i < numReverse.length; i++) {
            c = Verhoeff.d[c][Verhoeff.p[(i + 1) % 8][parseInt(numReverse[i])]];
        }
        return Verhoeff.inv[c].toString();
    }
}

export {
    generateVerifier,
    generateManualPairingCode,
}
