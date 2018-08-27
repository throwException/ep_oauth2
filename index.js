var ERR = require('async-stacktrace');
var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
var userManager = require('./UserManager');
var request = require('request');

// var settings = require('ep_etherpad-lite/node/utils/Settings').ep_oauth2;
var passport = require('passport');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;

// Environment Variables
var authorizationURL = process.env['EP_OAUTH2_AUTHORIZATION_URL'] || settings.users.oauth2.authorizationURL;
var tokenURL = process.env['EP_OAUTH2_TOKEN_URL'] || settings.users.oauth2.tokenURL;
var clientID = process.env['EP_OAUTH2_CLIENT_ID'] || settings.users.oauth2.clientID;
var clientSecret = process.env['EP_OAUTH2_CLIENT_SECRET'] || settings.users.oauth2.clientSecret;
var publicURL = process.env['EP_OAUTH2_PUBLIC_URL'] || settings.users.oauth2.publicURL;
var userinfoURL = process.env['EP_OAUTH2_USERINFO_URL'] || settings.users.oauth2.userinfoURL;
var usernameKey = process.env['EP_OAUTH2_USERNAME_KEY'] || settings.users.oauth2.usernameKey;
var idKey = process.env['EP_OAUTH2_USERID_KEY'] || settings.users.oauth2.useridKey;
var scope = process.env['EP_OAUTH2_SCOPE'] || settings.users.oauth2.scope;
var proxy = process.env['EP_OAUTH2_PROXY'] || settings.users.oauth2.proxy;
var state = process.env['EP_OAUTH2_STATE'] || settings.users.oauth2.state;

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

function initializeAuthAuthorState(username, authorId, authorName) {
  return {
    'id': authorId,
    'username': username,
    'shouldOverrideClient': authorId !== null,
    'state': 'INIT',
    'authorName': authorName
  }   
}

function setUsername(token, username) {
  authorManager.getAuthor4Token(token, function(err, author) {
    if (ERR(err)) {
    } else {
      authorManager.setAuthorName(author, username);
    }
  });
  return;
}

exports.expressConfigure = function(hook_name, context) {
  console.log('oauth2-expressConfigure');
  passport.use('hbp', new OAuth2Strategy({
    authorizationURL: authorizationURL,
    tokenURL: tokenURL,
    clientID: clientID,
    clientSecret: clientSecret,
    callbackURL: publicURL + '/auth/callback',
    scope: scope,
    proxy: proxy,
    state: state
  }, function(accessToken, refreshToken, profile, cb) {
    request.get({
      url: userinfoURL,
      auth: {
        bearer: accessToken
      },
      json: true
    }, function (error, response, data) {
      if (error) {
        return cb(error);
      }
      data.token = {
        type: 'bearer',
        accessToken: accessToken,
        refreshToken: refreshToken
      };

      var username = data[idKey]
      var displayName = data[usernameKey];
      userManager.setDisplay4Username(displayName, username);
      cb(null, data);
    });
  }));
  var app = context.app;
  app.use(passport.initialize());
  app.use(passport.session());
}

exports.expressCreateServer = function (hook_name, context) {
  console.info('oauth2-expressCreateServer');
  var app = context.app;
  app.get('/auth/callback', passport.authenticate('hbp', {
    failureRedirect: '/auth/failure'
  }), function(req, res) {
    req.session.user = req.user;
    res.redirect(req.session.afterAuthUrl);
  });
  app.get('/auth/failure', function(req, res) {
    res.send("<em>Authentication Failed</em>")
  });
  app.get('/auth/done', function(req, res) {
    res.send("<em>Authentication Suceeded</em>");
  });
}

exports.authenticate = function(hook_name, context, cb) {
  if (context.req.url.indexOf('/auth/') === 0) return context.next();
  context.req.session.afterAuthUrl = context.req.url;
  return passport.authenticate('session')(context.req, context.res, function(req, res) {
    if (context.req.session.user) {
      context.username = context.req.session.user[idKey];
      console.info('authenticated user ' + context.username + ' url ' + context.req.url + ' by session');

      return userManager.getDisplay4Username(context.username, function(err, displayName) {
        return userManager.getAuthor4Username(context.username, function(err, authorId) {
          context.req.session.auth_author = initializeAuthAuthorState(context.username, authorId, displayName);
          return cb([true]);
        });
      });

    } else {
      return passport.authenticate('hbp')(context.req, context.res, function(req, res) {
        context.username = context.req.session.user[idKey];
        console.info('authenticated user ' + context.username + ' url ' + context.req.url + ' by oauth2');
        return cb([true]);
      });
    }
  });
}

exports.handleMessage = function(hook_name, context, cb) {

  if( context.message.type === "CLIENT_READY" && context.client.request.session.auth_author ) {
    var req = context.client.request;
	
    if( req.session.auth_author.id
        && context.message.token
        && req.session.auth_author.state === 'INIT'
        && req.session.auth_author.shouldOverrideClient === true ) {
      // If session.auth_author.id is not null, and token is supplied, update database to
      // assign the token to the existing authorId
      userManager.setToken4Author(context.message.token, req.session.auth_author.id);
      console.info('Set token ' + context.message.token + ' for author ' + req.session.auth_author.id);
      req.session.auth_author.state = 'COMPLETE';
      return( cb([context.message]) );
    }

    if( context.message.token
        && req.session.auth_author.state === 'INIT'
        && req.session.auth_author.shouldOverrideClient === false ) {
      // If token is supplied, create author so we can stuff in the default username
      authorManager.getAuthor4Token(context.message.token, function(err, authorId) {
        if( authorId ) {
          req.session.auth_author.id = authorId;
	  userManager.setAuthor4Username(authorId, req.session.auth_author.username);
	  console.info('Set author ' + authorId + ' for user ' +  req.session.auth_author.username);
	  req.session.auth_author.state = 'COMPLETE';
	  authorManager.setAuthorName(authorId, req.session.auth_author.authorName, function(){			    
	    console.info('Set AuthorName to default value of ' + req.session.auth_author.authorName + ' for author ' + authorId);
	    return( cb([context.message]) );
          });		    
        } else {
          return( cb([context.message]) );
        }
      });
      return;
    }
  }

  if ( context.message.type == "COLLABROOM" && context.message.data.type == "USERINFO_UPDATE" ) {
    console.debug('oauth2.handleMessage: intercepted USERINFO_UPDATE and dropping it!');
    return cb([null]);
  }
  return cb([context.message]);
};
