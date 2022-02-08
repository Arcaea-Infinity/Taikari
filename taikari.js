/**
 *  Taikari frida tool
 *    (C) TheSnowfield 
 *
 *  Usage: frida -U Arcaea -l taikari.js
 *
 *  0.1 (02/07/2022)
 *    - SSL traffic capturing
 *    - Dump SSL certificate
 *  0.2 (02/08/2022)
 *    - hook challenge for test
 *    - challenge server
 *  0.3 (02/09/2022)
 *    - supported armv7 devices
 *    - fix pointer issue
 */

const config = {

  // hacktools
  hackTools: [
    { name: 'captureSSL', enabled: false, func: hackCaptureSSL },
    { name: 'dumpCertficate', enabled: false, func: hackDumpCertificate },
    { name: 'challengeHook', enabled: false, func: hackChallengeHook },
    { name: 'challengeServer', enabled: false, func: hackChallengeServer }
  ],

  // folders
  resFolder: {
    'htdoc': '/system/usr/taikari/htdoc',
    'library': '/system/usr/taikari/library'
  },

  // libraries
  useNative: true,
  useAsyncHttp: true,

  // specific arcaea version
  arcVersion: 'init',

  // specific taikari version
  taiVersion: '0.2',

  // pre-defined symbols
  libSymbols: {
    '3.11.2c_1019305_arm64-v8a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0x111caf4 },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0x122996c }, // curl_easy_perform also calling this
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0x1537c18 },
      { name: 'libcocos2dcpp.so!OnlineManager::fetchUser', proc: 0x11f92cc }
    ],
    '3.11.2c_1019305_armeabi-v7a': [
      { name: 'libcocos2dcpp.so!curl_easy_setopt', proc: 0xc19fbc },
      { name: 'libcocos2dcpp.so!easy_perform', proc: 0xe5a664 }, // curl_easy_perform also calling this
      { name: 'libcocos2dcpp.so!OnlineManager::sendHttpRequest', proc: 0xc43af1 },
      { name: 'libcocos2dcpp.so!OnlineManager::fetchUser', proc: 0xe2fba1 }
    ],
  }
};

// save original functions
const __console_log = console.log;
const __console_error = console.error;

// global initialize
(() => {
  console.log = (...msg) => __console_log(new Date().toLocaleString(), '[*]', msg);
  console.error = (...msg) => __console_error(new Date().toLocaleString(), '[!]', msg);
  console.info = (...msg) => __console_log(new Date().toLocaleString(), '[i]', msg);
  console.raw = (...msg) => __console_log(msg);

  // get version
  config.arcVersion = getArcaeaVersion();
  console.log(`current version is [${config.arcVersion}]`);

  // is supported
  if (!taiSupported()) {
    console.log('taikari currently not supported this device or arcaea, sorry.');
    return;
  }

  // load native helper
  if (config.useNative) {
    Module.load(`${resFolder('library')}/libtaikari.so`);
    console.info('library \'libtaikari.so\' scuessfully loaded.');
  }

  // load compiled dex library
  if (config.useAsyncHttp) {
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

})();


////// Hack Tools                                       
/////////////////////////////////////////////////////////

/**
 * dump certificate
 */
function hackDumpCertificate() {
  // hook curl_easy_setopt
  console.log('attaching [libcocos2dcpp.so!curl_easy_setopt]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!curl_easy_setopt'), {

    onEnter: function (args) {

      // CURLOPT_SSLCERT_BLOB
      if (args[1] == 0x9d63) {
        let blob = ptr(args[2]);

        // Calc pointers
        let cert = blob.readPointer();
        let length = blob.add(Process.pointerSize).readULong();
        let bytes = cert.readByteArray(length);

        console.log('Certificate');
        console.raw(hexdump(bytes));
      }
    }

  });
}

/**
 * ssl traffic capturing
 */
function hackCaptureSSL() {

  let pfunc = libSymbol('libcocos2dcpp.so!SSL_write');
  let SSL_write = new NativeFunction(pfunc, 'int', ['pointer', 'pointer', 'int']);
  let counter = 1;

  // traffic out
  console.log('raplacing [libcocos2dcpp.so!SSL_write]');
  Interceptor.replace(pfunc, new NativeCallback((ctx, buffer, length) => {

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
    return SSL_write(ctx, newBuffer, replace.length);

  }, 'int', ['pointer', 'pointer', 'int']));

  // traffic in
  console.log('attaching [libcocos2dcpp.so!SSL_read]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!SSL_read'), {
    onEnter: function (args) {
      this.buffer = ptr(args[1]);
    },

    onLeave: function (ret) {
      let data = this.buffer.readUtf8String(ret.toInt32());
      console.raw(data, '\n=================================');
    }
  });
}

/**
 * challenge hook
 */
function hackChallengeHook() {
  // assert
  if (!config.useNative) {
    console.error('challenge hook requires libtaikari.so!');
    console.error('please enable \'useNative\' from taikari.js');
    console.error(`then copy the libtaikari.so to \'${resFolder('library')}\'.`);
    return;
  }

  // hook user me
  console.log('attaching [libcocos2dcpp.so!OnlineManager::fetchUser]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!OnlineManager::fetchUser'), {

    onEnter: function (args) {

      // save lpthis
      this.lpthis = args[0];

      setTimeout(() => {
        let result = onlineManagerSendHttp(this.lpthis, 'https://arcapi-v2.lowiro.com/merikuri/17/lxnsnb');
        console.log(result, '?');
      }, 1000);
    }

  });
}

/**
 * challenge server
 */
function hackChallengeServer() {

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

  let _taskTable = {};
  let _taskIndex = 0;
  let _lpOnlineManager;

  // hook OnlineManager::fetchUser
  console.log('attaching [libcocos2dcpp.so!OnlineManager::fetchUser]');
  Interceptor.attach(libSymbol('libcocos2dcpp.so!OnlineManager::fetchUser'), {
    onEnter: (args) => { _lpOnlineManager = args[0]; console.info(`_lpOnlineManager = ${args[0]}`); }
  });

  // replace easy_perform
  console.log('replacing [libcocos2dcpp.so!easy_perform]');
  Interceptor.replace(libSymbol('libcocos2dcpp.so!easy_perform'),
    new NativeCallback((ctx, events) => {

      // block the request
      return 2; // CURLE_FAILED_INIT

    }, 'int', ['pointer', 'int']));

  // attach libcocos2dcpp.so!curl_easy_setopt
  Interceptor.attach(libSymbol('libcocos2dcpp.so!curl_easy_setopt'), {

    onEnter: function (args) {
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
    }

  });

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
    console.log('http server listening on :23333. (= w =)Zzz');
    let http = createHttpServer(23333, [
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

          // if not get _lpOnlineManager
          if (!_lpOnlineManager)
            throw new Error('please switch back to main menu again to get the pointer (user/me).');

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
          onlineManagerSendHttp(_lpOnlineManager,
            _params['path'], `Task: ${_taskname}`, _params['method'],
            _params['method'] == 'POST' ? _params['body'] : '');

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

/**
 * Get taikati version
 */
function taiVersion() {
  return config.taiVersion;
}

function taiSupported() {
  return !!(config.libSymbols[taiVersion()]) == false;
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
