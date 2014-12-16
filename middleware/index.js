var async = require('async');

module.exports = {
    isAuthorised: function (req, res, next) {
        var options = req.oauth2.options;
        var client = options.client;
        var accessToken = req.query.access_token;
        var key = null;
        var userId = null;

        async.series([
            function (callback) {
                client.get(accessToken, function (err, data) {
                    if (!data) {
                        return res.status(403).send('invalid accessToken');
                    }
                    var json = JSON.parse(data);
                    key = json.key;
                    userId = json.userId;
                    callback();
                });
            },
            function () {
                client.get(key, function (err, data) {
                    var redisAccessToken = JSON.parse(data).accessToken;
                    if (redisAccessToken !== accessToken) {
                        return res.status(403).send('another client is signed in');
                    }
                    req.userId = userId;
                    return next();
                });
            }
        ]);
    }
};