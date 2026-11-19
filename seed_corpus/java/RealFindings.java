// EXPECTED_FINDINGS: [{"primitive":"SHA1","category":"hash","line":5},{"primitive":"RSA","category":"signature","line":6},{"primitive":"AES","category":"symmetric-cipher","line":7,"keySizeBits":128,"mode":"ECB"},{"primitive":"bcrypt","category":"kdf","line":8},{"primitive":"HMAC-SHA256","category":"mac","line":9}]
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
MessageDigest.getInstance("SHA-1");
Signature.getInstance("SHA1withRSA");
Cipher.getInstance("AES/ECB/PKCS5Padding");
PasswordEncoder encoder = new BCryptPasswordEncoder(12);
Mac mac = Mac.getInstance("HmacSHA256");
