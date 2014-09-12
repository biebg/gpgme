var gpgme = require('./build/Release/gpgme');
exports.Sign = gpgme.Sign;
exports.Verify = gpgme.Verify;
exports.Export = gpgme.Export;
exports.isSigned = gpgme.isSigned;
