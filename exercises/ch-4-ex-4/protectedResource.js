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

var aliceFavorites = {
  movies: ['The Multidmensional Vector', 'Space Fights', 'Jewelry Boss'],
  foods: ['bacon', 'pizza', 'bacon pizza'],
  music: ['techno', 'industrial', 'alternative'],
};

var bobFavorites = {
  movies: ['An Unrequited Love', 'Several Shades of Turquoise', 'Think Of The Children'],
  foods: ['bacon', 'kale', 'gravel'],
  music: ['baroque', 'ukulele', 'baroque ukulele'],
};

app.get('/favorites', getAccessToken, requireAccessToken, function(req, res) {
  /*
   * Get different user information based on the information of who approved the token
   * 토큰을 승인한 유저 정보를 기반으로 다른 유저 정보를 얻음.
   */
  var scope = req.access_token.scope;

  if (req.access_token.user == 'alice') {
    res.json({ user: 'Alice', favorites: allowedFavorites(scope, aliceFavorites) });
  } else if (req.access_token.user == 'bob') {
    res.json({ user: 'Bob', favorites: allowedFavorites(scope, bobFavorites) });
  } else {
    var unknown = { user: 'Unknown', favorites: { movies: [], foods: [], music: [] } };
    res.json(unknown);
  }
});

/**
 * Scope 처리할 수 있게 헬퍼 함수 추가
 */
var allowedFavorites = function(scope, favorites) {
  console.log(`scope: ${scope}`);
  var allowedFavorites = { movies: [], foods: [], music: [] };

  if (__.contains(scope, 'movies')) {
    allowedFavorites.movies = favorites.movies;
  }

  if (__.contains(scope, 'foods')) {
    allowedFavorites.foods = favorites.foods;
  }

  if (__.contains(scope, 'music')) {
    allowedFavorites.music = favorites.music;
  }

  return allowedFavorites;
};


var server = app.listen(9002, 'localhost', function() {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
