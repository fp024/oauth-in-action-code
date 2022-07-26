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
  name: 'Protected Resource', description: 'This data has been protected by OAuth 2.0',
};


/**
 * 유입된 요청에서 액세스 토큰 스캔
 * @param req   요청
 * @param res   응답
 * @param next  요청을 계속 계속해서 처리하기 위해 호출 되는 함수
 */
var getAccessToken = function(req, res, next) {
  /*
   * Scan for an access token on the incoming request.
   */
  var inToken = null;
  var auth = req.headers['authorization']; // Express.js에서는 유입된 헤더이름을 소문자로 바꿈.

  // authorization 헤더가 있는 경우...
  if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
    inToken = auth.slice('bearer '.length); // bearer 헤더의 값을 추출

  } else if (req.body && req.body.access_token) { // 헤더는 없지만 POST form으로 토큰을 전달한 경우...
    inToken = req.body.access_token;

  } else if (req.query && req.query.access_token) {  // URL 파라미터로 토큰을 전달한 경우...
    inToken = req.query.access_token;

  }

  console.log('Incoming token: %s', inToken);

  // nosql 사용법: https://www.npmjs.com/package/nosql
  nosql.one().make(function(filter) {
    filter.where('access_token', inToken);
    filter.callback(function(err, token) {
      if (token) {
        console.log(`We found a matching token: ${inToken}`);
      } else {
        console.log('No matching token was found.');
      }
      req.access_token = token;
      next();
    });
  });

};


app.options('/resource', cors());

/*
 * Add the getAccessToken function to this handler
 * 
 * 핸들러로서 추가했음. getAccessToken() 가 핸들러로서 정상 처리되면
 * 요청객체에 access_token 값이 토큰값이 정상 설정되거나 null로 설정됨
 * 지면에는 cors()가 없는데... 저자님 예제 코드를 보니 cors 뒤에다 getAccessToken 을 배치하신 것 확인했다.
 */
app.post('/resource', cors(), getAccessToken, function(req, res) {
  /*
   * Check to see if the access token was found or not
   *
   * 토큰을 찾았는지 못찾았는지 여부 확인
   * 못찾았다면 401응답
   */
  if (req.access_token) {
    res.json(resource);
  } else {
    res.status(401).end();
  }
});

var server = app.listen(9002, 'localhost', function() {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
