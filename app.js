require('dotenv').config();
const { encrypt, decrypt } = require('./crypto-utils');

// Sample text to encrypt
const plainText = "Hello, this is a secure message!";

// Encrypt the text
try {
    const encryptedText = encrypt(plainText);
    console.log("Encrypted Text:", encryptedText);

    // Decrypt the text
    const decryptedText = decrypt(encryptedText);
    console.log("Decrypted Text:", decryptedText);
} catch (error) {
    console.error("Error:", error.message);
}
