const crypto = require('node:crypto');

const defaultKey = Buffer.from('a3K8Bx%2r8Y7#xDh', 'utf8');
const defaultKeyGCM = Buffer.from('{yxAHAY_Lm6pbC/<', 'utf8');

const ECB_ALG = 'aes-128-ecb';
const GCM_ALG = 'aes-128-gcm';

const GCM_NONCE = Buffer.from('5440784449675a516c5e6313', 'hex');
const GCM_AEAD = Buffer.from('qualcomm-test');

function encryptV2(data, key = defaultKeyGCM) {
    const cipher = crypto.createCipheriv(GCM_ALG, key, GCM_NONCE);
    cipher.setAAD(GCM_AEAD);
    const str = cipher.update(JSON.stringify(data), 'utf8', 'base64');
    const encPack = str + cipher.final('base64');
    const rawTag = cipher.getAuthTag();
    const encTag = rawTag.toString('base64').toString();
    return { encPack, encTag };
}

function decryptV2(data, key = defaultKeyGCM, tag) {
    const decipher = crypto.createDecipheriv(GCM_ALG, key, GCM_NONCE);
    decipher.setAAD(GCM_AEAD);
    if (tag) {
        const decTag = Buffer.from(tag, 'base64');
        decipher.setAuthTag(decTag);
    }
    const str = decipher.update(data, 'base64', 'utf8');
    const response = JSON.parse(str + decipher.final('utf8'));

    return response;
}

function encryptV1(data, key = defaultKey) {
    const cipher = crypto.createCipheriv(ECB_ALG, key, '');
    const str = cipher.update(JSON.stringify(data), 'utf8', 'base64');
    const pack = str + cipher.final('base64');
    return pack;
}

function decryptV1(data, key = defaultKey) {
    const decipher = crypto.createDecipheriv(ECB_ALG, key, '');
    const str = decipher.update(data, 'base64', 'utf8');
    const response = JSON.parse(str + decipher.final('utf8'));

    return response;
}

module.exports = {
    defaultKey,
    defaultKeyGCM,
    encryptV1,
    decryptV1,
    encryptV2,
    decryptV2
};