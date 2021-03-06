/**
 * Created by chandan.tiwari on 10/27/2015.
 */
var config = {
    "AWS_ACCOUNT_ID": "123412341234",
    "REGION": "eu-west-1",
    "BUCKET": "vedicbucket",
    "MAX_AGE": "10",
    "DDB_TABLE": "kundli_users",
    "IDENTITY_POOL_NAME": "LambdAuth",
    "DEVELOPER_PROVIDER_NAME": "kundli.vedicrishi.app",
    "EXTERNAL_NAME": "Kundli IO",
    "EMAIL_SOURCE": "mail@vedicrishiastro.com",
    "VERIFICATION_PAGE": "http://kundli.io/verify.html",
    "RESET_PAGE": "http://kundli.io/reset.html"
};

var AWS = require('aws-sdk');
var crypto = require('crypto');
var DOC = require('dynamodb-doc');
var dynamodb = new AWS.DynamoDB();
var ses = new AWS.SES();
var cognitoidentity = new AWS.CognitoIdentity();


var docClient = new DOC.DynamoDB();

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


function sendLostPasswordEmail(email, token, callback)
{
    var subject = 'Password Change Request for ' + config.EXTERNAL_NAME;
    var lostLink = config.RESET_PAGE + '?email=' + email + '&lost=' + token;
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
                        + 'Please <a href="' + lostLink + '">click here to reset your password</a> or copy & paste the following link in a browser:'
                        + '<br><br>'
                        + '<a href="' + lostLink + '">' + lostLink + '</a>'
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
    var params = {};
    params.TableName = config.DDB_TABLE;
    params.Key = {email : email};

    docClient.getItem(params, function(error, data){
        if(error)
        {
            return callback(error);
        }

        if('Item' in data)
        {
            return callback(null, {status: true, id:'USERFOUND', data: data.Item});
        }
        else
        {
            return callback(null, {status: false, id: 'USERNOTFOUND', msg: 'User does not exist in database!'})
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
                },
                lostToken: {
                    Action: 'DELETE'
                }
            }
        },
        callback);
}

function getCognitoToken(email, fn)
{
    var param = {
        IdentityPoolId: config.IDENTITY_POOL_ID,
        Logins: {} // To have provider name in a variable
    };
    param.Logins[config.DEVELOPER_PROVIDER_NAME] = email;
    cognitoidentity.getOpenIdTokenForDeveloperIdentity(param,
        function(err, data) {
            if (err) return fn(err); // an error occurred
            else fn(null, data.IdentityId, data.Token); // successful response
        });
}

exports.handler = function(event, context) {
    console.log(JSON.stringify(event));
    var operation = event.operation;
    var data = event.data;
    computeHash("hello", function(err, salt, hash) {

        if(err)
        {
            console.log(err);
            return context.fail('Error in hash: ' + err);
        }

        createNewUser('Chandan Nov', 'vedicrishiastro@gmail.com', hash, salt, function(err, token){

            if(err)
            {
                console.log(err);
                return context.fail('Error in creating '+ err);
            }

            console.log('Successfully created ! '+ token);

            context.succeed(true);
        });

    });

    /*switch(operation)
    {
        case 'CREATE_USER':
            // compute password hash
            // create and store user
            // send verification email
            async.waterfall([], function(error, response){

            });
            break;

        case 'VERIFY_USER':
            // get user
            // update user
            async.waterfall([], function(error, response){

            });
            break;

        case 'AUTHENTICATE_USER':
            // get user
            // compute password hash
            // check verification status
            // get cognito token id
            async.waterfall([], function(error, response){

            });
            break;
        case 'CHANGE_PASSWORD':
            // get user
            // compute hash for old password
            // compute hash for new password
            // update user password
            async.waterfall([], function(error, response){

            });
            break;
        case 'FORGOT_PASSWORD':
            // get user
            // store lost password token
            // send lost password token email
            async.waterfall([], function(error, response){

            });
            break;

        case 'RESET_PASSWORD':
            // get user
            // compute hash password
            // update user password
            async.waterfall([], function(error, response){

            });
            break;


    }*/
};