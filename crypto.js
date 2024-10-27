var CryptoJS = require("crypto-js");

// AES 加密
function aesEncrypt(text, key) {
    return CryptoJS.AES.encrypt(text, key);
}

// AES 解密
function aesDecrypt(encrypted, key) {
    var bytes = CryptoJS.AES.decrypt(encrypted, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// DES 加密
function desEncrypt(text, key) {
    return CryptoJS.DES.encrypt(text, key);
}

// DES 解密
function desDecrypt(encrypted, key) {
    var bytes = CryptoJS.DES.decrypt(encrypted, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// MD5 哈希
function md5Hash(text) {
    return CryptoJS.MD5(text);
}