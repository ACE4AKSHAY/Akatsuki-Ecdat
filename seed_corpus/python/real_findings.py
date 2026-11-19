# EXPECTED_FINDINGS: [{"primitive":"SHA1","category":"hash","line":4},{"primitive":"MD5","category":"hash","line":5},{"primitive":"RSA","category":"asymmetric-cipher","line":7,"keySizeBits":2048},{"primitive":"AES","category":"symmetric-cipher","line":9,"keySizeBits":128,"mode":"ECB"},{"primitive":"bcrypt","category":"kdf","line":12},{"primitive":"PBKDF2","category":"kdf","line":13},{"primitive":"TLSv1.2","category":"protocol","line":14}]
import hashlib
from cryptography.hazmat.primitives import hashes
hashlib.sha1(b"x")
hashlib.md5(b"x")
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(public_exponent=65537, key_size=2048)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
Cipher(algorithms.AES(b"k"*16), modes.ECB())
import bcrypt
import ssl
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
digest = hashlib.pbkdf2_hmac("sha256", password, salt, 600_000)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
