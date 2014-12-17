var async = require('async');

module.exports = {
    createToken: function(req, res, next){
        req.oauth2.token.create(req.oauth2.options, req.body, req.headers, function(err, data){
            if (err){
                res.status(err.status).send(err.body);
            }
            return res.json(data);
        });
    },
    isAuthorised: function (req, res, next) {
        var options = req.oauth2.options;
        var client = options.client;
        var accessToken = req.query.access_token;
        var key = null;
        var userId = null;

        if (!accessToken){ accessToken = req.session.accessToken; } // get from session - allow should be an option

        async.series([
            function (callback) {
                client.get('accesstoken:' + accessToken, function (err, data) {
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
                    req.oauth2.accessToken = {
                        userId: userId,
                        token: accessToken
                    }; // mainly here for legacy reasons
                    return next();
                });
            }
        ]);
    }
};