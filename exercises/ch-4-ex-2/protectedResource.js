var express = require('express');
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
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
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0',
};

var getAccessToken = function(req, res, next) {
  var inToken = null;
  var auth = req.headers['authorization'];
  if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
    inToken = auth.slice('bearer '.length);
  } else if (req.body && req.body.access_token) {
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }

  console.log('Incoming token: %s', inToken);
  nosql.one().make(function(builder) {
    builder.where('access_token', inToken);
    builder.callback(function(err, token) {
      if (token) {
        console.log('We found a matching token: %s', inToken);
      } else {
        console.log('No matching token was found.');
      }
      req.access_token = token;
      next();
      return;
    });
  });
};

var requireAccessToken = function(req, res, next) {
  if (req.access_token) {
    next();
  } else {
    res.status(401).end();
  }
};

var savedWords = [];

app.get('/words', getAccessToken, requireAccessToken, function(req, res) {
  /*
   * Make this function require the "read" scope
   * 이 함수를 "read" 스코프를 요구하도록 만들어야함.
   */
  if (__.contains(req.access_token.scope, 'read')) {
    res.json({ words: savedWords.join(' '), timestamp: Date.now() });
  } else {
    console.log('GET /words 호출시 read 권한이 없음');
    // 토큰에 포함된 범위가 포함되어있지 않으면 WWW-Authenticate 헤더를 통해 에러를 반환
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="read"');
    res.status(403).end();
  }

});

app.post('/words', getAccessToken, requireAccessToken, function(req, res) {
  /*
   * Make this function require the "write" scope
   * 이 함수를 "write" 스코프를 요구하도록 만들어야함.
   */
  if (__.contains(req.access_token.scope, 'write')) {
    if (req.body.word) {
      savedWords.push(req.body.word);
    }
    res.status(201).end();
  } else {
    console.log('POST /words 호출시 write 권한이 없음');
    // 토큰에 포함된 범위가 포함되어있지 않으면 WWW-Authenticate 헤더를 통해 에러를 반환
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="write"');
    res.status(403).end();
  }
});

app.delete('/words', getAccessToken, requireAccessToken, function(req, res) {
  /*
   * Make this function require the "delete" scope
   * 이 함수를 "delete" 스코프를 요구하도록 만들어야함.
   */
  if (__.contains(req.access_token.scope, 'delete')) {
    savedWords.pop();
    res.status(204).end();
  } else {
    console.log('DELETE /words 호출시 delete 권한이 없음');
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="delete"');
    res.status(403).end();
  }
});

var server = app.listen(9002, 'localhost', function() {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
