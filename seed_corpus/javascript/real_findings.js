// EXPECTED_FINDINGS: [{"primitive":"SHA1","category":"hash","line":3},{"primitive":"RSA","category":"asymmetric-cipher","line":4,"keySizeBits":2048},{"primitive":"AES","category":"symmetric-cipher","line":5,"keySizeBits":128,"mode":"ECB"},{"primitive":"HMAC-SHA256","category":"mac","line":6},{"primitive":"TLSv1.2","category":"protocol","line":8}]
const crypto = require('crypto');
const h = crypto.createHash('sha1');
const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const c = crypto.createCipheriv('aes-128-ecb', Buffer.alloc(16), null);
const mac = crypto.createHmac('sha256', key);
const tls = require('tls');
const server = tls.createServer({ minVersion: 'TLSv1.2' });
