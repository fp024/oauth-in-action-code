var express = require('express');
var url = require('url');
var bodyParser = require('body-parser');
var randomstring = require('randomstring');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
};

// client information
var clients = [
  /*
   * Enter client information here
   * 클라이언트 정보 입력: 정적으로 인가서버에 클라이언트를 등록 (예제 단순회를 위해서 그러신 것 같다.)
   * 클라이언트 정보는 일반적으로 DB에 저장하지만, 예제 동작의 확인 편리성을 위해 변수에 저장
   */
  {
    'client_id': 'oauth-client-1',
    'client_secret': 'oauth-client-secret-1',
    'redirect_uris': ['http://localhost:9000/callback'],
  },

];

var codes = {};

var requests = {};

/**
 * 클라이언트 ID로 클라이언트 조회
 * @param clientId  클라이언트 ID
 * @returns {*} 클라이언트 객체, 해당 클라이언트 ID에 해당하는 객체가 없다면 undefined 반환
 */
var getClient = function(clientId) {
  return __.find(clients, function(client) {
    return client.client_id == clientId;
  });
};

app.get('/', function(req, res) {
  res.render('index', { clients: clients, authServer: authServer });
});

// 인가 포인트 역활
app.get('/authorize', function(req, res) {
  /*
   * Process the request, validate the client, and send the user to the approval page
   * 요청을 처리하고 클라이언트를 확인하고 사용자를 승인 페이지로 보냅니다.
   */

  // 1. 인가를 요청한 클라이언트를 확인
  var client = getClient(req.query.client_id);

  if (!client) {
    // 등록되지 않은 클라이언트라면...
    res.render('error', { error: 'Unknown client' });
    return;
  } else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) { // 등록된 클라이언트지만 리다이렉트 URI정보가 다르다면...
    res.render('error', { error: 'Invalid redirect URI' });
    return;
  }

  // 사용자가 승인한 이후에 다시 참조할 수 있도록 현재 요청에 대한 고유 ID 생성
  // CSRF 공격 차단 효과를 위해서도 사용
  var reqid = randomstring.generate(8);
  // 해당 요청 ID를 키로 요청 쿼리를 저장
  requests[reqid] = req.query;

  res.render('approve', { client: client, reqid: reqid });

});

app.post('/approve', function(req, res) {
  /*
   * Process the results of the approval page, authorize the client
   * 승인 페이지 결과 처리, 클라이언트 권한 부여
   */
  // '/authorize' 에서 만들어서 사용자 브라우저 결과에 hidden으로 저장되었던 reqid를 요청객체에서 가져옴.
  var reqid = req.body.reqid;
  var query = requests[reqid];
  delete requests[reqid];

  if (!query) {
    res.render('error', { error: 'No matching authorization request' });
    return;
  }


  if (req.body.approve) { // 사용자가 Approve 버튼 클릭

    if (query.response_type == 'code') { // 인가 코드 그랜트 타입에 대한 처리
      var code = randomstring.generate(8);

      codes[code] = { request: query };

      // 클라이언트 보호를 위해 state 전달했던 것을 다시 그대로 클라이언트에 전달.
      var urlParsed = buildUrl(query.redirect_uri, {
        code: code,
        state: query.state,
      });
      res.redirect(urlParsed);
      return;

    } else {
      var urlParsed = buildUrl(query.redirect_uri, {
        error: 'unsupported_response_type',
      });

      res.redirect(urlParsed);
      return;
    }

  } else { // 사용자가 Deny 버튼 클릭
    // 클라이언트의 리다이렉트 URI에 error 파라미터를 설정해서 리다이렉트
    // 이런식의 URL이 됨:  http://localhost:9000/callback?error=access_denied
    var urlParsed = buildUrl(query.redirect_uri, {
      error: 'access_denied',
    });

    res.redirect(urlParsed);
    return;
  }


});

// 토큰 앤드 포인트
app.post('/token', function(req, res) {
  /*
   * Process the request, issue an access token
   * 요청을 처리하고 엑세스 토큰을 발행
   */

  const auth = req.headers['authorization'];
  let clientId = null;
  let clientSecret = null;

  if (auth) {
    const clientCredentials = decodeClientCredentials(auth);
    clientId = clientCredentials.id;
    clientSecret = clientCredentials.secret;
  }

  // form으로 clientId가 전달 되었는지 검사
  if (req.body.client_id) {
    // 클라이언트가 헤더로도 전달하고 form로도 전달하면 에러로 간주.
    if (clientId) {
      res.status(401).json({ error: 'invalid_client' });
    }
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  console.log(`POST /token 에서의 유입된 clientId: ${clientId}, clientSecret: ${clientSecret}`);

  // 클라이언트가 등록된 클라이언트 목록에 없다면 에러반환
  const client = getClient(clientId);
  if (!client) {
    res.status(401).json({ error: 'invalid_client' });
    return;
  }


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


/**
 * HTTP Authorization 헤더 값을 디코드하여 인증정보 위한 유틸리티 함수
 * @param auth HTTP Authorization 헤더 값
 * @returns {{id: string, secret: string}}
 */
var decodeClientCredentials = function(auth) {
  var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
  var clientId = querystring.unescape(clientCredentials[0]);
  var clientSecret = querystring.unescape(clientCredentials[1]);
  return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function() {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
