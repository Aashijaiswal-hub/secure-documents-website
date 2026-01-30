require('dotenv').config({ path: '.env' });
const { encryptBuffer, decryptBuffer } = require('./utils/crypto');

console.log("--- STARTING CRYPTO TEST ---");

const originalText = "This is a Top Secret Government Document. Aadhar: 1234-5678";
const originalBuffer = Buffer.from(originalText);

console.log(`Original: ${originalText}`);

try {
    console.log("\n1. Encrypting...");
    const { encryptedBuffer, iv, authTag, wrappedKey } = encryptBuffer(originalBuffer);
    
    console.log(`- Encrypted Size: ${encryptedBuffer.length} bytes`);
    console.log(`- IV: ${iv}`);
    console.log(`- AuthTag: ${authTag}`);
    console.log(`- Wrapped Key: ${wrappedKey}`);

    console.log("\n2. Decrypting...");
    const decryptedBuffer = decryptBuffer(encryptedBuffer, iv, authTag, wrappedKey);
    const decryptedText = decryptedBuffer.toString();

    console.log(`Decrypted: ${decryptedText}`);

    if (originalText === decryptedText) {
        console.log("\nSUCCESS: Data matches perfectly! ✅");
    } else {
        console.log("\nFAILURE: Data mismatch! ❌");
    }

    console.log("\n3. Tamper Test (Simulating Hacker)...");
    encryptedBuffer[0] = encryptedBuffer[0] + 1;
    try {
        decryptBuffer(encryptedBuffer, iv, authTag, wrappedKey);
    } catch (err) {
        console.log(`SUCCESS: Tampering detected! Error: ${err.message} ✅`);
    }

} catch (error) {
    console.error("TEST FAILED:", error);
}