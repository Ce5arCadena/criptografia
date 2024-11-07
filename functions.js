const forge = require('node-forge');
const CryptoJS = require('crypto-js');

const encrypt = (user, password, key) => {
    if (!password || !user || !key) {
        return {error: 'No se pudo encriptar la contraseña'};
    };

    const data = `${user} ${password}`;
    const dataEncrypted = CryptoJS.AES.encrypt(data, key).toString();
    return {'dataCifrada': dataEncrypted, message: `Los datos cifrados son: ${user} y ${password}`};
};

const decrypt = (dataEncrypted, key) => {
    const bytes = CryptoJS.AES.decrypt(dataEncrypted, key);
    
    if(bytes.sigBytes > 0){
        const decryptedData = bytes.toString(CryptoJS.enc.Utf8);
        return {message: `Datos descifrados: ${decryptedData}`};
    } else {
        return {error: 'No se pudo desencriptar la información'};
    }
};

const asymmetricEncryption = (user, password) => {
    let message = '';
    const rsa = forge.pki.rsa;

    const keys = rsa.generateKeyPair({bits: 2048, e: 0x10001});

    let publicKey = keys.publicKey;
    let privateKey = keys.privateKey; 

    const data = `${user} ${password}`;
    message = publicKey.encrypt(data, 'RSA-OAEP');
    
    const newPrivateKey = forge.pki.privateKeyToPem(privateKey);
    return {message: `Datos encriptada: ${forge.util.encode64(message)}.`, key: `Llave para desencriptar: ${newPrivateKey}`};
};

const asymmetricDecryption = (dataEncrypted, privateKey) => {
    try {
        const dataDecode = forge.util.decode64(dataEncrypted);
        const newFormatPrivateKey = forge.pki.privateKeyFromPem(privateKey);
        const messageDecrypt = newFormatPrivateKey.decrypt(dataDecode, 'RSA-OAEP');
    
        return {message: `Usuario y clave desencriptada: ${messageDecrypt}.`};
    } catch (error) {
        return {error: `Ocurrió un error al desencriptar los datos: ${error}.`};
    }
};

module.exports = {
    encrypt,
    decrypt,
    asymmetricEncryption,
    asymmetricDecryption
}