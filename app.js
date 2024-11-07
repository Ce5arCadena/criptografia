const cors = require('cors');
const express = require('express');

const {encrypt, decrypt, asymmetricEncryption, asymmetricDecryption} = require('./functions');

const app = express();

app.use(cors());
app.use(express.json());

app.post('/encriptar', (req,res) => {
    const { user, password, key} = req.body;
    const responseEncryptedPassword = encrypt(user, password, key);

    res.json(responseEncryptedPassword);
});

app.post('/desencriptar', (req, res) => {
    const { dataEncrypted, key } = req.body;

    const responseDecrypted = decrypt(dataEncrypted, key);
    res.json(responseDecrypted);
});

// Cifrado asimetrico
app.post('/encriptar-asimetrico', (req,res) => {
    const { user, password } = req.body;
    const responseEncryptedPassword = asymmetricEncryption(user, password);

    res.json(responseEncryptedPassword);
});

app.post('/desencriptar-asimetrico', (req,res) => {
    const { data_encrypted, privateKey } = req.body;
    const responseEncryptedPassword = asymmetricDecryption(data_encrypted, privateKey);

    res.json(responseEncryptedPassword);
});

app.listen('5555', () => {
    console.log('App corriendo =)');
});

module.exports = app;