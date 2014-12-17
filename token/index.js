var async = require('async'),
    crypto = require('crypto');

module.exports = {
    create: function (options, body, headers, next) {
        var model = options.model;
        var clientId = null;
        var clientSecret = null;
        var client = null;
        var user = null;
        var key = null;
        var value = {};

        async.series([
            function (callback) {
                // basic validation
                if (!headers || !headers.authorization) {
                    return next({status: 403, body: 'No authorization header passed'});
                }
                var pieces = headers.authorization.split(' ', 2);
                if (!pieces || pieces.length !== 2) {
                    return next({status: 403, body: 'Authorization header is corrupted'});
                }
                if (pieces[0] !== 'Basic') {
                    return next({status: 403, body: 'Unsupported authorization method: ' + pieces[0]});
                }
                pieces = new Buffer(pieces[1], 'base64').toString('ascii').split(':', 2);
                if (!pieces || pieces.length !== 2) {
                    return next({status: 403, body: 'Authorization header has corrupted data'});
                }
                clientId = pieces[0];
                clientSecret = pieces[1];
                callback();
            },
            function (callback) {
                // client
                model.client.getByCredentials(clientId, clientSecret, function (result) {
                    if (!result) {
                        return next({status: 403, body: 'Invalid client credentials'});
                    }
                    client = result;
                    callback();
                })
            },
            function (callback) {
                // user
                model.user.getByCredentials(body.username, body.password, function (result) {
                    if (!result) {
                        return next({status: 403, body: 'Invalid user credentials'});
                    }
                    user = result;
                    callback();
                });
            },
            function (callback) {
                // create key and value (session:userId:clientId)
                key = 'session:' + user.id + ':' + client.id;
                value = {
                    accessToken: crypto.randomBytes(32).toString('hex'),
                    refreshToken: crypto.randomBytes(64).toString('hex')
                };
                callback();
            },
            function (callback) {
                // create redis record for key -> value
                options.client.setex(key, options.ttl, JSON.stringify(value), callback);
            },
            function (callback) {
                // create redis record for accessToken -> key
                options.client.setex('accesstoken:' + value.accessToken, options.ttl, JSON.stringify({
                    key: key,
                    userId: user.id
                }), callback);
            },
            function () {
                return next(null, value);
            }
        ]);
    }
};