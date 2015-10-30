/**
 * Created by chandan.tiwari on 10/27/2015.
 */
var AWS = require('aws-sdk');
var crypto = require('crypto');
var config = require('./config.json');
var dynamodb = new AWS.DynamoDB();
var ses = new AWS.SES();

function computeHash(password, salt, fn)
{
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

function sendVerificationEmail(email, token, callback)
{
    var subject = 'Verify your kundli.io account';
    var verificationLink = config.VERIFICATION_PAGE + '?email=' + encodeURIComponent(email) + '&verify=' + token;
    ses.sendEmail({
        Source: config.EMAIL_SOURCE,
        Destination: {
            ToAddresses: [
                email
            ]
        },
        Message: {
            Subject: {
                Data: subject
            },
            Body: {
                Html: {
                    Data: '<html><head>'
                    + '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />'
                    + '<title>' + subject + '</title>'
                    + '</head><body>'
                    + 'Please <a href="' + verificationLink + '">click here to verify your email address</a> or copy & paste the following link in a browser:'
                    + '<br><br>'
                    + '<a href="' + verificationLink + '">' + verificationLink + '</a>'
                    + '</body></html>'
                }
            }
        }
    }, callback);
}


function createNewUser(name, email, password, salt, callback)
{
    var len = 128;
    crypto.randomBytes(len, function(err, token) {
        if (err) return fn(err);
        token = token.toString('hex');
        dynamodb.putItem({
            TableName: config.DDB_TABLE,
            Item: {
                email: {
                    S: email
                },
                created_at: {
                    N: new Date().getTime()
                },
                name: {
                    S: name
                },
                passwordHash: {
                    S: password
                },
                passwordSalt: {
                    S: salt
                },
                verified: {
                    BOOL: false
                },
                verifyToken: {
                    S: token
                }
            },
            ConditionExpression: 'attribute_not_exists (email)'

        }, function(err, data)
        {
            if (err)
            {
                return callback(err);
            }
            else
            {
                callback(null, token);
            }
        });
    });
}

function getUserByEmail(email, callback)
{
    dynamodb.getItem({
        TableName: config.DDB_TABLE,
        Key: {
            email: {
                S: email
            }
        }
    }, function(err, data)
    {
        if (err) return callback(err);
        else
        {
            if ('Item' in data)
            {
                var verified = data.Item.verified.BOOL;
                var verifyToken = null;
                if (!verified)
                {
                    verifyToken = data.Item.verifyToken.S;
                }
                callback(null, verified, verifyToken);
            } else
            {
                callback(null, null); // User not found
            }
        }
    });
}

function updateUserToken(email, callback)
{
    dynamodb.updateItem({
            TableName: config.DDB_TABLE,
            Key: {
                email: {
                    S: email
                }
            },
            AttributeUpdates: {
                verified: {
                    Action: 'PUT',
                    Value: {
                        BOOL: true
                    }
                },
                verifyToken: {
                    Action: 'DELETE'
                }
            }
        },
        callback);
}

function updatePasswordToken(email, password, salt, callback)
{
    dynamodb.updateItem({
            TableName: config.DDB_TABLE,
            Key: {
                email: {
                    S: email
                }
            },
            AttributeUpdates: {
                passwordHash: {
                    Action: 'PUT',
                    Value: {
                        S: password
                    }
                },
                passwordSalt: {
                    Action: 'PUT',
                    Value: {
                        S: salt
                    }
                }
            }
        },
        callback);
}

function storeLostPasswordToken(email, callback)
{
    // Bytesize
    var len = 128;
    crypto.randomBytes(len, function(err, token) {
        if (err)
        {
            return callback(err);
        }
        token = token.toString('hex');
        dynamodb.updateItem({
                TableName: config.DDB_TABLE,
                Key: {
                    email: {
                        S: email
                    }
                },
                AttributeUpdates: {
                    lostToken: {
                        Action: 'PUT',
                        Value: {
                            S: token
                        }
                    }
                }
            },
            function(err, data) {
                if (err) return callback(err);
                else callback(null, token);
            });
    });
}

function resetPassword(email, password, salt, callback)
{

}

exports.handler = function(event, context) {
    console.log(JSON.stringify(event));
    var operation = event.operation;
    var data = event.data;

    switch(operation)
    {
        case 'CREATE_USER':
            break;

        case 'AUTHENTICATE_USER':
            break;

        case 'FORGOT_PASSWORD':
            break;

        case 'RESET_PASSWORD':
            break;

        case 'VERIFY_USER':
            break;
    }
};