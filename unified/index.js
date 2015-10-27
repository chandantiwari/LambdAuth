/**
 * Created by chandan.tiwari on 10/27/2015.
 */
var AWS = require('aws-sdk');
var crypto = require('crypto');
var config = require('./config.json');

function computeHash(password, salt, fn) {
    // Bytesize
    var len = 128;
    var iterations = 4096;

    if (3 == arguments.length) {
        crypto.pbkdf2(password, salt, iterations, len, fn);
    } else {
        fn = salt;
        crypto.randomBytes(len, function(err, salt) {
            if (err) return fn(err);
            salt = salt.toString('base64');
            crypto.pbkdf2(password, salt, iterations, len, function(err, derivedKey) {
                if (err) return fn(err);
                fn(null, salt, derivedKey.toString('base64'));
            });
        });
    }
}


function sendEmail(email, token, callback)
{

}


function createNewUser(name, email, password, salt, callback)
{

}

function getUserByEmail(email, callback)
{

}

function updateUserToken(email, callback)
{

}

function updatePasswordToken(email, password, salt, callback)
{

}

function storeLostPasswordToken(email, callback)
{

}

function resetPassword()
{

}

exports.handler = function(event, context) {
    console.log(JSON.stringify(event));


};