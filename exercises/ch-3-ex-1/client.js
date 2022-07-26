var express = require('express');
var request = require('sync-request');
var url = require('url');
var qs = require('qs');
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require('randomstring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
};

// client information

/*
 * Add the client information in here
 */
var client = {
  client_id: 'oauth-client-1',              // client_id, client_secret를 입력해 클라이언트에 넣어줌.
  client_secret: 'oauth-client-secret-1',
  redirect_uris: ['http://localhost:9000/callback'],
};

var protectedResource = 'http://localhost:9002/resource';

// 크로스 사이트 공격방지용 state 파라미터
var state = null;

var access_token = null;
var scope = null;

app.get('/', function(req, res) {
  res.render('index', { access_token: access_token, scope: scope });
});

// 인가 엔드포인트로 연결
app.get('/authorize', function(req, res) {

  state = randomstring.generate();
  console.log('authorize에서 생성한 state 값: %s', state);
  /*
   * Send the user to the authorization server
   * 사용자를 인가 서버로 보냄
   */
  var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state: state,
  });

  res.redirect(authorizeUrl);
});

// 인가 요청에 대한 응답 처리
app.get('/callback', function(req, res) {

  // 전달했었던 state 검사
  console.log('callback에서의 state 값: %s', req.query.state);
  if (req.query.state != state) {
    res.render('error', { error: 'State value did not match' });
    return;
  }

  /*
   * Parse the response from the authorization server and get a token
   * 인가 서버로 부터 응답을 해석하고 토큰을 얻음.
   */
  var code = req.query.code;


  // 인가 코드를 추출해 토큰 엔드 포인트로 직접 HTTP POST 전송해야함.
  var form_data = qs.stringify({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: client.redirect_uris[0],
  });

  // 인가 요청에 redirect uri가 포함되면 토큰을 요청할 때도 동일한 URI를 함께 전달해야함.
  // 그래서 form_data안에 redirect_uri를 그대로 포함시킴


  // - HTTP 요청이 form encoding 되었다는 것을 나타내기 위한 해더
  // - Basic 인증을 위한 Authorization 헤더는 사용자 이름과 비밀번호를 콜론으로 연결한뒤 Base64로 인코딩한 문자열
  // - 사용자 이름과 비밀번호는 모두 URL 인코딩 되야함.
  var headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret),
  };


  // 인가 서버의 엔드 포인트로 POST 요청 보내 응답을 받음.
  var tokRes = request('POST', authServer.tokenEndpoint, {
    body: form_data,
    headers: headers,
  });

  var body = JSON.parse(tokRes.getBody());

  // 추출한 엑세스 토큰을 이후에도 사용할 수 있도록 저장.
  access_token = body.access_token;

  console.log(`access_token: ${body.access_token}`);
  console.log(`scope: ${body.scope}`);
  console.log(`token_type: ${body.token_type}`);
  res.render('index', { access_token: body.access_token, scope: scope });

});

app.get('/fetch_resource', function(req, res) {
  /*
   * Use the access token to call the resource server
   */
});

var buildUrl = function(base, options, hash) {
  var newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, function(value, key, list) {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

var encodeClientCredentials = function(clientId, clientSecret) {
  return Buffer.from(
    querystring.escape(clientId) + ':' + querystring.escape(clientSecret),
  ).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function() {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
