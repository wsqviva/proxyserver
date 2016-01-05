'use strict';
var fs = require('fs');

var config = {
  addProxyHeader: true,
  // 正向代理访问控制开关
  ipControl: false,
  hostControl: false,

  listen: [
    {
      // 123.57.95.22
      ip: '127.0.0.1',
      port: 8080
    }
  ]
};

// 反向代理到www.baidu.com
config.hostFilters = {
  "www.baidu.com:80": {
    "proxyto": "123.57.95.22",
    "validuser": {
      "admin": "admin",
      "wusiquan": "wusiquan"
    },
    "description":"Very secret project here ;-)"
  }
};

// 普通代理对ip的限制
config.ipList = ['125.39.112.7'];

// 普通代理对
config.blackList = [];

module.exports = config;