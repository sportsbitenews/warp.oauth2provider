# warp-oauth2provider

## Overview
warp-oauth2provider is a simple but secure OAuth2 provider for ExpressJS 4 and Redis. A user can be logged in once per client.

Contains an example implementation, where the model is currently a static file, can be easily replaced with a SequelizeJS model (or similar, as long as it is implemented with a getByCredential method for the client and user object).

Implement as below;

	var express = require('express'),
	    redis = require('redis'),
	    bodyParser = require('body-parser');
	var app = express();
	var oauth2lib = require('./warp-oauth2provider'),
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

## Limitations
Currently only supports username / password authentication.

## Feedback
Contact us on info@wearereasonablepeople.com