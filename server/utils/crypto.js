const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEK = Buffer.from(process.env.MSG_ENCRYPTION_MASTER_KEY, 'hex'); 
const IV_LENGTH = 16; 

/**
 * 1. WRAP KEY (Encrypt the Data Key)
 * Uses the Master Key (KEK) to encrypt the unique file key (DEK).
 * We use AES-256-ECB here since the Key is small and random (no patterns).
 */
const wrapKey = (dek) => {
    const cipher = crypto.createCipheriv('aes-256-ecb', KEK, null);
    return Buffer.concat([cipher.update(dek), cipher.final()]).toString('hex');
};

/**
 * 2. UNWRAP KEY (Decrypt the Data Key)
 * Recovers the unique file key (DEK) using the Master Key.
 */
const unwrapKey = (wrappedKeyHex) => {
    const cipher = crypto.createDecipheriv('aes-256-ecb', KEK, null);
    const encryptedKey = Buffer.from(wrappedKeyHex, 'hex');
    return Buffer.concat([cipher.update(encryptedKey), cipher.final()]);
};

/**
 * 3. ENCRYPT BUFFER (Main Function)
 * Encrypts a file buffer using a fresh Data Key (DEK).
 */
exports.encryptBuffer = (buffer) => {
    const dek = crypto.randomBytes(32);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, dek, iv);

    const encryptedBuffer = Buffer.concat([
        cipher.update(buffer),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag().toString('hex');

    const wrappedKey = wrapKey(dek);

    return {
        encryptedBuffer,
        iv: iv.toString('hex'),
        authTag,
        wrappedKey
    };
};

exports.decryptBuffer = (encryptedBuffer, ivHex, authTagHex, wrappedKeyHex) => {

    const dek = unwrapKey(wrappedKeyHex);
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);    
    decipher.setAuthTag(authTag);

    const decryptedBuffer = Buffer.concat([
        decipher.update(encryptedBuffer),
        decipher.final()
    ]);

    return decryptedBuffer;
};