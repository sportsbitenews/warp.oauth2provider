var async = require('async'),
    crypto = require('crypto');

module.exports = {
    create: function (req, res) {
        var options = req.oauth2.options;
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
                if (!req.headers || !req.headers.authorization) {
                    return res.status(403).send('No authorization header passed');
                }
                var pieces = req.headers.authorization.split(' ', 2);
                if (!pieces || pieces.length !== 2) {
                    return res.status(403).send('Authorization header is corrupted');
                }
                if (pieces[0] !== 'Basic') {
                    return res.status(403).send('Unsupported authorization method: ', pieces[0]);
                }
                pieces = new Buffer(pieces[1], 'base64').toString('ascii').split(':', 2);
                if (!pieces || pieces.length !== 2) {
                    return res.status(403).send('Authorization header has corrupted data');
                }
                clientId = pieces[0];
                clientSecret = pieces[1];
                callback();
            },
            function (callback) {
                // client
                model.client.getByCredentials(clientId, clientSecret, function (result) {
                    if (!result) {
                        return res.status(403).send('Invalid client credentials');
                    }
                    client = result;
                    callback();
                })
            },
            function (callback) {
                // user
                model.user.getByCredentials(req.body.username, req.body.password, function (result) {
                    if (!result) {
                        return res.status(403).send('Invalid user credentials');
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
                // return json object
                return res.json(value);
            }
        ]);
    }
};