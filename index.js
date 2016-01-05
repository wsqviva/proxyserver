'use strict';

var http = require('http');
var util = require('util');
var url = require('url');
var config = require('./config/config');

function preventLoop(request, response) {
  if(request.headers.proxy == 'node.jtlebi') {
    response.writeHead(500);
    response.write('Proxy loop!');
    response.end();
    return false;
  }
  // 做个标记
  request.headers.proxy = 'node.jtlebi';
  return true;
}

function hostAllowed(host) {
  var blackList = config.blackList;

  if (config.hostControl) {
    return !blackList.some(function(_host) {
      return _host.test(host);
    });
  }

  return !config.hostControl;
}

function ipAllowed(ip) {
  var ipList = config.ipList;

  if (config.ipControl) {
    return ipList.some(function(_ip) {
      return ip == _ip;
    });
  }

  return !config.ipControl;
}

function securityFilter(request, response) {
  if(request.headers.host === undefined || request.method === undefined || request.url === undefined) {
    return false;
  }
  return true;
}

// header decoding
function authenticate(request) {
  var userAccout = {
    'user': 'anonymous',
    'pass': ''
  };
  // authorization: 'Basic d3VzaXF1YW46d3VzaXF1YW4='
  var authorization = request.headers.authorization;
  var basic;

  if (authorization && authorization.indexOf('Basic ') === 0) {
    basic = (new Buffer(authorization.split(' ')[1], 'base64').toString());
    basic = basic.split(':');
    userAccout.user = basic[0];
    userAccout.pass = "";
    for(var i = 1; i< basic.length; i++) {
      userAccout.pass += basic[i];
    }
  }

  return userAccout;
}

/**
 * decode host and port info from header
 *
 * {
 *   protocol: null,
 *   slashes: null,
 *   auth: null,
 *   host: null,
 *   port: null,
 *   hostname: null,
 *   hash: null,
 *   search: null,
 *   query: null,
 *   pathname: '123.57.95.22',
 *   path: '123.57.95.22',
 *   href: '123.57.95.22'
 * }
 */
// TODO: 还是会有问题哦
function decodeUrl(requestUrl) {
  var parseUrl = url.parse(requestUrl);
  var out = {};
  out.host = parseUrl.hostname || parseUrl.href;
  out.port = parseUrl.port || 80;
  out.path = parseUrl.path == parseUrl.href ? '/' : parseUrl.path;
  return out;
}

// encode
//function encodeHost(action) {
//  return action.host + ((action.port == 80) ? '' : ':' + action.port);
//}

function hanleProxyRule(rule, action, userAccount) {
  // handle authorization
  if ('validuser' in rule) {
    if (!(userAccount.user in rule.validuser) || (rule.validuser[userAccount.user] != userAccount.pass)) {
      action.action = 'authenticate';
      action.msg = rule.description || '';
      return action;
    }
  }

  // handle real actions
  if ("redirect" in rule) {
    action = decodeUrl(rule.redirect);
    action.action = "redirect";
  } else if ("proxyto" in rule) {
    action = decodeUrl(rule.proxyto);
    action.action = "proxyto";
  }

  return action;
}

function handleProxyRoute(requestUrl, userAccount) {
  var action = decodeUrl(requestUrl);
  var hostFilters = config.hostFilters;
  var rule;

  // default action
  action.action = "proxyto";

  // try to find a matching rule
  // rule of the form "www.abc.com:port"
  if (action.host + ':' + action.port in hostFilters) {
    rule = hostFilters[action.host + ':' + action.port];
    action = hanleProxyRule(rule, action, userAccount);
  // rule of the form "www.abc.com"
  } else if (action.host in hostFilters) {
    rule = hostFilters[action.host];
    action = hanleProxyRule(rule, action, userAccount);
  //rule of the form "*:port"
  } else if ("*:" + action.port in hostFilters) {
    rule = hostFilters['*:'+action.port];
    action = hanleProxyRule(rule, action, userAccount);
  // default rule "*"
  } else if ("*" in hostFilters) {
    rule = hostFilters['*'];
    action = hanleProxyRule(rule, action, userAccount);
  }

  return action;
}

// 代理, 比如在本地启动本服务, 浏览器设置127.0.0.1:8080为代理
function serverCb(request, response) {
  if (!securityFilter) {
    // 打印错误
    return;
  }

  var ip = request.connection.remoteAddress;
  if (!ipAllowed(ip)) {
    // 打印错误
    return;
  }

  if (!hostAllowed(request.url)) {
    // 打印错误
    return;
  }

  // preventLoop
  preventLoop(request, response);
  if (!request) {
    util.log('Loop detected');
    return;
  }

  // 开始请求
  util.log(ip + ': ' + request.method + ' ' + request.headers.host + ' => ' + request.url);

  var userAccount = authenticate(request);
  var action = handleProxyRoute(request.url, userAccount);

  // handle action
  if (action.action == "redirect") {
    actionRedirect(response, action.host);
  } else if (action.action == "proxyto") {
    actionProxy(request, response, action);
  } else if (action.action == "authenticate") {
    actionAuthenticate(response, action.msg);
  }
}

function actionRedirect(response, host) {
  util.log('Redirecting to ' + host);
  response.writeHead(301, {
    'Location': 'http://' + host
  });
  response.end();
}

function actionAuthenticate(response, msg) {
  response.writeHead(401, {
    'WWW-Authenticate': 'Basic realm=\"' + msg + '\"'
  });
  response.end();
}

// TODO: 有空用charles看下,favicon里的referer是不是本身就带上的
function actionProxy(request, response, action) {
  var headers = request.headers;
  if (config.addProxyHeader) {
    if (headers['X-Forwarded-For'] !== undefined) {
      headers['X-Forwarded-For'] = request.connection.remoteAddress + ', ' + headers['X-Forwarded-For'];
    } else {
      headers['X-Forwarded-For'] = request.connection.remoteAddress;
    }
  }

  var options = {
    hostname: action.host,
    port: action.port,
    path: action.path,
    family: 4,
    method: request.method,
    headers: headers
  };

  var proxy = http.request(options);
  proxy.on('response', function(proxyResponse) {
    proxyResponse.on('data', function(chunk) {
      response.write(chunk);
    });

    proxyResponse.on('end', function() {
      response.end();
    });

    response.writeHead(proxyResponse.statusCode, proxyResponse.headers);
  });

  request.on('data', function(chunk) {
    proxy.write(chunk);
  });

  request.on('end', function() {
    proxy.end();
  });


}

config.listen.forEach(function(listen) {
  util.log("Starting reverse proxy server on port '" + listen.ip+':'+listen.port);
  http.createServer(serverCb).listen(listen.port, listen.ip);
});
