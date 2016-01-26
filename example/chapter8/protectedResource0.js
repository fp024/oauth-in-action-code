var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");
var __ = require('underscore');
var base64url = require('base64url');
var jose = require('jsrsasign');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

var sharedTokenSecret = "shared token secret!";

var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

var protectedResources = {
		"resource_id": "protected-resource-1",
		"resource_secret": "protected-resource-secret-1"
};

var authServer = {
	introspectionEndpoint: 'http://localhost:9001/introspect'
};


var getAccessToken = function(req, res, next) {
	// check the auth header first
	var auth = req.headers['authorization'];
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		// not in the header, check in the form body
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	console.log('Incoming token: %s', inToken);
	/*
	nosql.one(function(token) {
		if (token.access_token == inToken) {
			return token;	
		}
	}, function(err, token) {
		if (token) {
			console.log("We found a matching token: %s", inToken);
		} else {
			console.log('No matching token was found.');
		}
		req.access_token = token;
		next();
		return;
	});
	*/
	/*
	//var signatureValid = jose.jws.JWS.verify(inToken, new Buffer(sharedTokenSecret).toString('hex'), ['HS256']);
	var pubKey = jose.KEYUTIL.getKey(rsaKey);
	var signatureValid = jose.jws.JWS.verify(inToken, pubKey, ['RS256']);
	if (signatureValid) {
		console.log('Signature validated.');
		var tokenParts = inToken.split('.');
		var payload = JSON.parse(base64url.decode(tokenParts[1]));
		console.log('Payload', payload);
		if (payload.iss == 'http://localhost:9001/') {
			console.log('issuer OK');
			if ((Array.isArray(payload.aud) && _.contains(payload.aud, 'http://localhost:9002/')) || 
				payload.aud == 'http://localhost:9002/') {
				console.log('Audience OK');
				
				var now = Math.floor(Date.now() / 1000);
				
				if (payload.iat <= now) {
					console.log('issued-at OK');
					if (payload.exp >= now) {
						console.log('expiration OK');
						
						console.log('Token valid!');
		
						req.access_token = payload;
						
					}
				}
			}
			
		}
			

	}
	next();
	return;
	*/
	
	var form_data = qs.stringify({
		token: inToken
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer(querystring.escape(protectedResources.resource_id) + ':' + querystring.escape(protectedResources.resource_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.introspectionEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		console.log('Got introspection response', body);
		var active = body.active;
		if (active) {
			req.access_token = body;
		}
	}
	next();
	return;
	
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
}; 

app.get("/helloWorld", cors(), getAccessToken, function(req, res){
	if (req.access_token) {
		//text/html
		if (req.query.language == "en") {
			res.send('Hello World');
		} else if (req.query.language == "de") {
			res.send('Hallo Welt');
		} else if (req.query.language == "it") {
			res.send('Ciao Mondo');
		} else if (req.query.language == "fr") {
			res.send('Bonjour monde');
		} else if (req.query.language == "es") {
			res.send('Hola mundo');
		} else {
			res.send("Error, invalid language: "+ req.query.language);
		}
	}
	
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 