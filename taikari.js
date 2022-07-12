/**
 *  Taikari frida tool
 *    (C) TheSnowfield 
 *
 *  Usage: frida -U -f "moe.low.arc" --no-pause -l taikari.js
 */

const config = {

  // hacktools
  hackTools: [
    { name: 'captureSSL', enabled: false, func: hackCaptureSSL },
    { name: 'dumpCertficate', enabled: false, func: hackDumpCertificate },
    { name: 'hookOnlineManagerCtor', enabled: true, func: hackOnlineManagerCtor },
    { name: 'challengeHookTest', enabled: false, func: hackChallengeHookTest },
    { name: 'challengeServer', enabled: true, func: hackChallengeServer },
    { name: 'pretendArcVersion', enabled: false, func: hackPretendArcVersion },
    { name: 'pretendDeviceId', enabled: false, func: hackPretendDeviceId },
  ],

  // folders
  resFolder: {
    'htdoc': '/system/usr/taikari/htdoc',
    'library': '/system/usr/taikari/library'
  },

  // libraries
  useNative: true,
  useJLHttp: true,

  // challenge server
  challengeHttpPort: 23333,

  // specific arcaea version
  arcVersion: 'init',

  // pretend 
  pretendDeviceId: 'ffffffffffffffff',
  pretendArcVersion: '6.1.6c (Taikari)',

  // pre-defined symbols
  libSymbols: {
    '3.11.2c_1019305_arm64-v8a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x111caf4 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x122996c }, // curl_easy_perform also calling this
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x11f273c },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x1537c18 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0x125226c }
    ],
    '3.11.2c_1019305_armeabi-v7a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0xc19fbc },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0xe5a664 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x9e2cbd },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0xc43af1 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0xd3beb1 }
    ],
    '3.12.0c_1020007_armeabi-v7a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x41c264 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x3bca58 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x364971 },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x3584c1 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0x7b0009 }
    ],
    '3.12.0c_1020007_arm64-v8a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0xe112e4 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x6ff1e0 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0xbf1234 },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x567064 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0xd463fc }
    ],
    '3.12.1c_1020010_armeabi-v7a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x6a946c },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x6e3fa8 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x38a0c1 },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x6fcf05 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0x5F4CA9 }
    ],
    '3.12.1c_1020010_arm64-v8a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0xbc7dc4 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0xe711b0 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0xc583dc },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x8080cc },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0xde3cc0 }
    ],
    '3.12.2c_1020517_armeabi-v7a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x7e0bb8 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x5ee218 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x4153c5 },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x60c9d5 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0x5d9d9d }
    ],
    '3.12.2c_1020517_arm64-v8a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x6e4564 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x765350 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x69a380 },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x8ba05c },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0xbd898c }
    ],
    '3.12.6c_1032000_arm64-v8a': [ // not working
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0xa43f64 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0xbf22a4 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0xd7a2b0 },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0xcb1088 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0xacc900 }
    ],
    '4.0.0c_1050010_armeabi-v7a' : [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x3f9008 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x411a60 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x4301c5 },
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x31b7a1 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0x786a8d }
    ],
    '4.0.1c_1050014_armeabi-v7a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x80d24c },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x8263f4 },
      { name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc: 0x3b7b6d }, 
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x6234b1 },
      { name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc: 0x8853b9 }
    ],
    '4.0.0c_1050010_arm64-v8a' : [//wip
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x788fbc },
      //{ name: 'libcocos2dcpp.so!easy_perform', proc:  }, // fastcall: sub_CB2768; func(easy handle already used...): sub_D80818
      //{ name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc:  },
      //{ name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc:  },
      //{ name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc:  }
    ],
    '4.0.1c_1050014_arm64-v8a': [//wip
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0xa15c48 },
      //{ name: 'libcocos2dcpp.so!easy_perform', proc:  },// fastcall: sub_CDA784; func(easy handle already used...): sub_CF479C
      //{ name: 'libcocos2dcpp.so!OnlineManager::OnlineManager', proc:  }, 
      //{ name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc:  },
      //{ name: 'libcocos2dcpp.so!OnlineManager::setFavoriteCharacter', proc:  }
    ]
  }
};

// save original functions
const __console_log = console.log;
const __console_error = console.error;
console.log = (...msg) => __console_log(new Date().toLocaleString(), '[*]', msg);
console.error = (...msg) => __console_error(new Date().toLocaleString(), '[!]', msg);
console.info = (...msg) => __console_log(new Date().toLocaleString(), '[i]', msg);
console.raw = (...msg) => __console_log(msg);

// start when cocos_android_app_init reached
Interceptor.attach(Module.findExportByName('liblog.so', '__android_log_print'), {

  onEnter: (args) => {

    let _logstr = args[2].readUtf8String();
    if (_logstr != 'cocos_android_app_init') return;
    console.raw('');

    // get version
    config.arcVersion = getArcaeaVersion();
    console.log(`current version is [${config.arcVersion}]`);

    // is supported
    if (!taiSupported()) {
      console.log('sorry, taikari currently not supported this device or arcaea.');
      return;
    }

    // load native helper
    if (config.useNative) {
      Module.load(`${resFolder('library')}/${Process.arch}/libtaikari.so`);
      console.info('library \'libtaikari.so\' scuessfully loaded.');
    }

    // load compiled dex library
    if (config.useJLHttp) {
      Java.openClassFile(`${resFolder('library')}/jlhttp.dex`).load();
      console.info('dex file \'jlhttp.dex\' scuessfully loaded.');
    }

    // apply hack tools where enabled
    config.hackTools.forEach(tool => {
      if (tool.enabled) {
        tool.func();
        console.info(`tool \'${tool.name}\' enabled.`);
      }
    });

  }
});

////// Hack Tools                                       
/////////////////////////////////////////////////////////

/**
 * dump certificate
 */
function hackDumpCertificate() {

  // hook curl_easy_setopt
  console.log('attaching [libcocos2dcpp.so!curl_easy_setopt]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!curl_easy_setopt'), {

    onEnter: (args) => {

      // CURLOPT_SSLCERT_BLOB
      if (args[1] == 0x9d63) {
        let blob = args[2];

        // Calc pointers
        let cert = blob.readPointer();
        let length = blob.add(Process.pointerSize).readULong();
        let bytes = cert.readByteArray(length);

        console.log('Certificate');
        console.raw(hexdump(bytes));
      }

      // CURLOPT_KEYPASSWD
      if (args[1] == 0x272a) {
        console.log('Certificate Pwd');
        console.log(args[2].readUtf8String());
        return;
      }
    }

  });
}

/**
 * ssl traffic capturing
 */
function hackCaptureSSL() {

  let _sslWrite = libSymbol('libcocos2dcpp.so!SSL_write');
  let _sslWriteOld = new NativeFunction(_sslWrite, 'int', ['pointer', 'pointer', 'int']);
  let counter = 1;

  // traffic out
  console.log('raplacing [libcocos2dcpp.so!SSL_write]');
  Interceptor.replace(_sslWrite, new NativeCallback((ctx, buffer, length) => {

    counter++;

    // remove gzip compress feature
    let replace = buffer.readUtf8String(length).replace('Accept-Encoding: deflate, gzip\r\n', '');
    let newBuffer = Memory.allocUtf8String(replace);

    // filter multiple calls
    if (counter % 2 == 0) {
      console.raw('\n====', new Date().toLocaleString(), '====');
      console.raw(replace, '\n');
    }

    // write data to
    return _sslWriteOld(ctx, newBuffer, replace.length);

  }, 'int', ['pointer', 'pointer', 'int']));

  // traffic in
  console.log('attaching [libcocos2dcpp.so!SSL_read]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!SSL_read'), {
    onEnter: (args) => {
      this.buffer = ptr(args[1]);
    },

    onLeave: (ret) => {
      let data = this.buffer.readUtf8String(ret.toInt32());
      console.raw(data, '\n=================================');
    }
  });
}

/**
 * pretend arcara version
 */
function hackPretendArcVersion() {

  console.log('attaching [libcocos2dcpp.so!Java_low_moe_AppActivity_setAppVersion]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!Java_low_moe_AppActivity_setAppVersion'), {

    onEnter: (args) => {
      // replacing the argument
      args[2] = jniNewStringUTF(args[0],
        Memory.allocUtf8String(config.pretendArcVersion));
    }

  });
}

/**
 * pretend arcaea device id
 */
function hackPretendDeviceId() {

  console.log('attaching [libcocos2dcpp.so!Java_low_moe_AppActivity_setDeviceId]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!Java_low_moe_AppActivity_setDeviceId'), {

    onEnter: (args) => {
      // replacing the argument
      args[2] = jniNewStringUTF(args[0],
        Memory.allocUtf8String(config.pretendDeviceId));
    }

  });
}

/**
 * hook online manager constructor
 */
function hackOnlineManagerCtor() {

  console.log('attaching [libcocos2dcpp.so!OnlineManager::OnlineManager]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!OnlineManager::OnlineManager'), {

    // save the pointer
    onEnter: (args) => {
      global.lpOnlineManager = args[0];
      console.info(`lpOnlineManager = ${args[0]}`);
    }

  });
}

/**
 * challenge hook test
 */
function hackChallengeHookTest() {

  // assert native helper loaded
  if (!config.useNative) {
    console.error('challenge hook test requires libtaikari.so!');
    console.error('please enable the \'useNative\'');
    return;
  }

  // assert hookOnlineManagerCtor is enabled
  if (!checkIfEnabled('hookOnlineManagerCtor')) {
    console.error('please enable the \'hookOnlineManagerCtor\'!');
    return;
  }

  // hook set favorite character
  console.log('attaching [libcocos2dcpp.so!OnlineManager::setFavoriteCharacter]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!OnlineManager::setFavoriteCharacter'), {

    onEnter: (args) => {

      let _result = onlineManagerSendHttp(global.lpOnlineManager,
        'https://arcapi-v2.lowiro.com/merikuri/17/lxnsnb');

      console.log('test result:', _result);
    }

  });
}

/**
 * challenge server
 */
function hackChallengeServer() {

  // assert native helper loaded
  if (!config.useNative) {
    console.error('challenge server requires libtaikari.so!');
    console.error('please enable the \'useNative\'');
    return;
  }

  // assert http dex loaded
  if (!config.useJLHttp) {
    console.error('challenge server requires jlhttp.dex!');
    console.error('please enable the \'useJLHttp\'');
    return;
  }

  // assert challengeHook is not enabled
  if (checkIfEnabled('challengeHook')) {
    console.error('please disable the \'challengeHook\'!');
    return;
  }

  // assert dumpCertficate is not enabled
  if (checkIfEnabled('dumpCertficate')) {
    console.error('please disable the \'dumpCertficate\'!');
    return;
  }

  // assert hookOnlineManagerCtor is enabled
  if (!checkIfEnabled('hookOnlineManagerCtor')) {
    console.error('please enable the \'hookOnlineManagerCtor\'!');
    return;
  }

  let _taskTable = {};
  let _taskIndex = 0;
  let _apiPrefix = ""; // https://arcapi-v2.lowiro.com/merikuri/17/

  // replace easy_perform
  console.log('replacing [libcocos2dcpp.so!easy_perform]');
  Interceptor.replace(libSymbol('libcocos2dcpp.so!easy_perform'),
    new NativeCallback((ctx, events) => {

      // block the request
      return 2; // CURLE_FAILED_INIT

    }, 'int', ['pointer', 'int']));

  // attach libcocos2dcpp.so!curl_easy_setopt
  console.log('attach [libcocos2dcpp.so!curl_easy_setopt]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!curl_easy_setopt'), {

    onEnter: (args) => {
      // CURLOPT_HTTPHEADER
      if (args[1] == 0x2727) {

        let _header = curlParseSlist(args[2]);

        let _taskIndex = _header.find((header) => {
          if (header.startsWith('Task'))
            return true;
        });

        // task index
        if (!_taskIndex) return;
        _taskIndex = _taskIndex.substr(6).replace(/\s/, '');

        let _challenge = _header.find((header) => {
          if (header.startsWith('X-Random-Challenge'))
            return true;
        });

        // challenge string
        _challenge = _challenge.substr(20).replace(/\s/, '');

        // return challenge
        _taskTable[_taskIndex].resolve(_challenge);
        return;
      }

      // CURLOPT_URL
      if (args[1] == 0x2712) {

        if (!_apiPrefix) {
          let _urlstr = args[2].readUtf8String();

          // match the result
          let _match = _urlstr.match(/https:\/\/(\S.*?\/){3}/);
          if (_match.length != 2) {
            console.error(`error while detecting, preberly an invalid url. ${_urlstr}`);
            return;
          }

          // set the result
          _apiPrefix = _match[0];
          console.log(`arcapi detected. ${_apiPrefix}`);
        }

        return;
      }

    }

  });

  // the online manager has not been
  // constructed now, thus wait for 2s.
  setTimeout(() => {
    // arcapi prefix automatic detection
    console.info('auto detecting arcapi...');
    onlineManagerSetFavChar(global.lpOnlineManager, 1);
  }, 2000);

  // start the server
  Java.perform(() => {

    function createHttpServer(port, routes) {
      let _httpServer = Java.use('net.freeutils.httpserver.HTTPServer');
      let _contextHandler = Java.use('net.freeutils.httpserver.HTTPServer$ContextHandler');

      // create instance
      let _server = _httpServer.$new(port);
      let _vhost = _server.getVirtualHost(null);

      // disable index generation
      _vhost.setAllowGeneratedIndex(false);

      // add routes
      routes.forEach(route => {

        // make class name
        let _clasName = route.path.split('/').join('.');
        if (_clasName == '.') _clasName = '.index';

        // implements the interface
        let _myHandler = Java.registerClass({
          name: `moe.awa.taikari.handler${_clasName}`,
          implements: [_contextHandler],
          methods: {
            serve: (request, response) => {

              console.log(request.getURI());

              try {
                // replace header
                response.getHeaders()
                  .replace('Arcaea', `${config.arcVersion}`);

                // custom handler
                route.handler(request, response);
              }

              catch (e) {
                console.error(e.stack);
                response.send(500, 'Internal Server Error. _(:3) z)_');
              }

              return 0;
            }
          }
        });

        // add context handler
        _vhost.addContext(route.path, _myHandler.$new(),
          Java.array('java.lang.String', route.methods));
      });

      // destroy while reload the script
      Script.bindWeak(_server, _ => _server.stop());

      return _server;
    }

    // create a http server
    console.log(`http server listening on :${config.challengeHttpPort}. (= w =)Zzz`);
    let http = createHttpServer(config.challengeHttpPort, [
      {
        path: '/',
        methods: ['GET'],
        handler: (request, response) => {

          let _fileStream = Java.use("java.io.FileInputStream");
          let _fileCls = Java.use('java.io.File');

          let _index = `${resFolder('htdoc')}/index.html`;
          let _bodyLength = _fileCls.$new(_index).length();
          let _fs = _fileStream.$new(_index);

          response.getHeaders().add('Content-Length', _bodyLength.toString());
          response.sendHeaders(200);
          response.sendBody(_fs, _bodyLength, null);
          response.close();

          _fs.close();
        }

      },
      {
        path: '/v1/generate',
        methods: ['GET'],
        handler: (request, response) => {

          // append header
          response.getHeaders().add('Content-Type', 'application/json; charset=utf-8');

          // increase the index
          ++_taskIndex;
          if (_taskIndex > 10000) _taskIndex = 0;

          // create a new task
          let _resolve;
          let _promise = new Promise(r => _resolve = r);
          let _taskname = _taskIndex.toString();

          _taskTable[_taskname] = {
            task: _promise,
            resolve: _resolve,
            response: Java.retain(response) // must retain this object
          };

          // check the arguments
          let _params = parseJavaMap(request.getParams());
          _params['method'] = _params['method'].toUpperCase();

          if (!_params['method'] || !_params['path']) {
            response.send(200, JSON.stringify({ status: -1, message: 'lack arguments.' }));
            return;
          }

          // check the post body
          if (_params['method'] == 'POST' && !_params['body']) {
            response.send(200, JSON.stringify({ status: -2, message: 'lack argument \'body\'.' }));
            return;
          }

          // send http request
          onlineManagerSendHttp(global.lpOnlineManager,
            `${_apiPrefix}${decodeURIComponent(_params['path'])}`,
            `Task: ${_taskname}`, _params['method'],
            _params['method'] == 'POST' ? decodeURIComponent(_params['body']) : '');

          // wait for promise
          _promise.then((data) => {

            try {
              Java.perform(_ => {
                let _response = _taskTable[_taskname].response;
                _response.send(200, JSON.stringify({ status: 0, content: { challenge: data } }));
                _response.close();
              })
            } catch (e) {
              console.log(e.stack);
            }
          });

        }
      }
    ]);

    http.start();
  });

}

////// Utils                                            
/////////////////////////////////////////////////////////

function taiSupported() {
  return !(config.libSymbols[getArcaeaVersion()]) == false;
}

/**
 * Send a http request
 * @param {*} lpthis instance of OnlineManager 
 * @param {string} url url to access
 * @param {string} method http method GET or POST
 * @param {string} body POST body
 * @returns 
 */
function onlineManagerSendHttp(lpthis, url, headers = '', method = 'GET', body = '') {

  // native help function
  let _helpfunc = libSymbol('libtaikari.so!sendHttpRequest');
  _helpfunc = new NativeFunction(_helpfunc, 'int64', ['pointer', 'pointer', 'pointer', 'int', 'pointer', 'pointer']);

  // send function
  let _callfunc = libSymbol('libcocos2dcpp.so!OnlineManager::sendHttpRequest');

  // prepare resources
  let _url = Memory.allocUtf8String(url);
  let _method = method.toUpperCase() == 'GET' ? 0x00 : 0x01;
  let _headers = Memory.allocUtf8String(headers);
  let _postbody = Memory.allocUtf8String(body);

  // call send http request
  return _helpfunc(lpthis, _callfunc, _url, _method, _headers, _postbody);
}

/**
 * Set favirate character
 */
function onlineManagerSetFavChar(lpthis, cid) {

  // native help function
  let _helpfunc = libSymbol('libtaikari.so!setFavoriteCharacter');
  _helpfunc = new NativeFunction(_helpfunc, 'int64', ['pointer', 'pointer', 'int']);

  // calling function
  let _callfunc = libSymbol('libcocos2dcpp.so!OnlineManager::setFavoriteCharacter');

  // call set favorite character
  return _helpfunc(lpthis, _callfunc, cid);
}

/**
 * Check if a hack tool enabled
 * @param {string} name name of a hack tool
 */
function checkIfEnabled(name) {
  let enabled = false;

  config.hackTools.forEach((tool) => {
    if (tool.name == name) enabled = tool.enabled;
  });

  return enabled;
}

/**
 * Find symbol
 * @param {string} name function name
 * @returns NativePointer
 */
function libSymbol(name) {

  let _split = name.split('!');
  if (_split.length != 2) return null;

  let _procName = _split[1];
  let _moduleName = _split[0];
  let _procAddress;

  // proc address from frida
  _procAddress = Module.findExportByName(_moduleName, _procName);
  if (_procAddress instanceof NativePointer) return _procAddress;

  // module base
  let _moduleBase = Module.getBaseAddress(_moduleName);
  if (!_moduleBase) return null;

  // proc address from config
  config.libSymbols[config.arcVersion].forEach((def) => {
    if (def.name == name) _procAddress = def.proc;
  });

  if (_procAddress != 0) return _moduleBase.add(_procAddress);
  return null;
}

/**
 * Get resource folder
 * @param {string} name 
 */
function resFolder(name) {
  return config.resFolder[name];
}

function getArcaeaVersion() {

  let _arcver = '';
  let _arcbuild = '';
  let _architecture = '';

  // arcaea version
  Java.perform(() => {
    let _buildConf = Java.use('moe.low.arcdev.BuildConfig');
    _arcver = _buildConf.class.getDeclaredField('VERSION_NAME').get(null);
    _arcbuild = _buildConf.class.getDeclaredField('VERSION_CODE').get(null);
  });

  // android architecture
  Java.perform(() => {
    let _osBuild = Java.use('android.os.Build');
    _architecture = _osBuild.class.getDeclaredField('CPU_ABI').get(null);
  });

  return `${_arcver}_${_arcbuild}_${_architecture}`;
}

/**
 * parse curl slist
 * @param {NativePointer} lpslist 
 */
function curlParseSlist(lpslist) {

  // struct curl_slist {
  //   char* data;
  //   curl_slist* next;
  // }

  let _slist = lpslist;
  let _data = _slist.readPointer();
  let _next = _slist.add(Process.pointerSize).readPointer();
  let _result = [];

  // enumerate the linked table
  while (!_next.isNull()) {
    _result.push(_data.readUtf8String());

    // next
    _slist = _next;
    _data = _slist.readPointer();
    _next = _slist.add(Process.pointerSize).readPointer();
  }

  // dont forget the last one
  return _result.concat(_data.readUtf8String());
}

/**
 * parse java map
 * @param  map 
 */
function parseJavaMap(map) {
  var _keys = map.keySet();
  var _itor = _keys.iterator();
  var _array = {};

  while (_itor.hasNext()) {
    var _key = _itor.next();
    _array[_key.toString()] = map.get(_key).toString();
  }
  return _array;
}

/**
 * New string utf
 * @param env JNI env
 * @param str string 
 * @returns 
 */
function jniNewStringUTF(env, str) {
  const _jniIndex = 167;
  const _funcAddress = env.readPointer().add(_jniIndex * Process.pointerSize).readPointer();
  let newStringUTF = new NativeFunction(_funcAddress, 'pointer', ['pointer', 'pointer']);

  return newStringUTF(env, str);
}
