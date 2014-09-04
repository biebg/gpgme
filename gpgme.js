var gpgme = require('./build/Release/gpgme');
var fs = require('fs');
exports.Sign = gpgme.Sign;
exports.Verify = gpgme.Verify;
exports.Export = gpgme.Export
gpgme.Sign('yuansc', "hello", function (err, result) {
	console.log(err, result);
})