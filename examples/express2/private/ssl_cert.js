var crypto = require('crypto'), fs = require("fs");

exports.privateKey = fs.readFileSync('./private/privatekey.pem').toString();
exports.certificate = fs.readFileSync('./private/certificate.pem').toString();
