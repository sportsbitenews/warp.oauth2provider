var express = require('express'),
    redis = require('redis'),
    bodyParser = require('body-parser');
var app = express();
var oauth2lib = require('../index'),
    oauth2 = new oauth2lib({
        client: redis.createClient(),
        model: {
            client: require('./models/client.js'),
            user: require('./models/user.js')
        },
        ttl: 600
    });

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(oauth2.inject());

app.get('/secure', oauth2.middleware.isAuthorised, function(req, res) {
    res.json({
        userId: req.userId
    });
});

app.get('/insecure', function(req, res) {
    res.json(true);
});

app.post('/oauth/token', oauth2.token.create);

var server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;

    console.log('Example app listening at http://%s:%s', host, port);
});