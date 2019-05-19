// we have to know all of these properties before calling the encryption method
const hash = "SHA-256";
const salt = "SALT";
const password = "PASSWORD";
const iteratrions = 1000;
const keyLength = 48;

async function getDerivation(hash, salt, password, iterations, keyLength) {
  const textEncoder = new TextEncoder("utf-8");
  const passwordBuffer = textEncoder.encode(password);
  const importedKey = await crypto.subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveBits"]);

  const saltBuffer = textEncoder.encode(salt);
  const params = {name: "PBKDF2", hash: hash, salt: saltBuffer, iterations: iterations};
  const derivation = await crypto.subtle.deriveBits(params, importedKey, keyLength*8);
  return derivation;
}

async function getKey(derivation) {
  const ivlen = 16;
  const keylen = 32;
  const derivedKey = derivation.slice(0, keylen);
  const iv = derivation.slice(keylen);
  const importedEncryptionKey = await crypto.subtle.importKey('raw', derivedKey, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
  return {
    key: importedEncryptionKey,
    iv: iv
  }
}

async function encrypt(text, keyObject) {
    const textEncoder = new TextEncoder("utf-8");
    const textBuffer = textEncoder.encode(text);
    const encryptedText = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: keyObject.iv }, keyObject.key, textBuffer);
    return encryptedText;
}

async function decrypt(encryptedText, keyObject) {
    const textDecoder = new TextDecoder("utf-8");
    const decryptedText = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: keyObject.iv }, keyObject.key, encryptedText);
    return textDecoder.decode(decryptedText);
}

async function encryptData(text) {
	const derivation = await getDerivation(hash, salt, password, iteratrions, keyLength);
	const keyObject = await getKey(derivation);
	const encryptedObject = await encrypt(JSON.stringify(text), keyObject);
	return encryptedObject;
}

async function decryptData(encryptedObject) {
	const derivation = await getDerivation(hash, salt, password, iteratrions, keyLength);
	const keyObject = await getKey(derivation);
	const decryptedObject = await decrypt(encryptedObject, keyObject);
	return decryptedObject;
}

const userObject = { "id": "7f85f6db-7894-418d-996c-f3f4ac61bf8e", "sellerScore": 80, "salesCount": 5 }
const encData = await encryptData(userObject);
const decryptedData = await decryptData(encData);
console.log(decryptedData) // will print { "id": "7f85f6db-7894-418d-996c-f3f4ac61bf8e", "sellerScore": 80, "salesCount": 5 }
