'use strict';

/*
 * advertising-id-exfil.js
 *
 * Purpose:
 *   Detect whether the Android Advertising ID (AAID/GAID) appears in
 *   outbound network requests.
 *
 * Coverage:
 *   - Google AdvertisingIdClient
 *   - java.net.HttpURLConnection
 *   - OkHttp 3/4
 *   - Retrofit indirectly through OkHttp
 *   - WebView / Cordova Java-side traffic
 *   - GET / POST / headers / query strings / request bodies
 *
 * Important:
 *   This is a detection hook. It does not decrypt TLS traffic.
 *
 * Example:
 *   frida -U -f com.example.app -l advertising-id-exfil.js
 */

'use strict';

const CONFIG = {
    LOG_ALL_NETWORK: false,

    // Maximum bytes/chars retained from request bodies.
    MAX_BODY: 256 * 1024,

    // Detect transformations in addition to plaintext.
    CHECK_URL_ENCODED: true,
    CHECK_BASE64: true,
    CHECK_HASHES: true,

    // Useful when a framework chunks a POST body.
    CHUNK_CACHE_SIZE: 512 * 1024,

    // Avoid dumping large binary payloads.
    MAX_PRINT: 4096
};

let advertisingIds = [];
let observedRequests = {};
let outputStreams = {};
let requestCounter = 0;

function log(s) {
    console.log('[AAID] ' + s);
}

function warn(s) {
    console.error('[AAID][!] ' + s);
}

function safeString(v) {
    try {
        if (v === null || v === undefined)
            return '';

        return String(v);
    } catch (_) {
        return '';
    }
}

function truncate(s, n) {
    s = safeString(s);
    return s.length > n ? s.substring(0, n) + '...' : s;
}

function addAdvertisingId(id, source) {
    id = safeString(id).trim();

    if (!id || id.length < 8)
        return;

    if (advertisingIds.indexOf(id) === -1) {
        advertisingIds.push(id);
        log('Advertising ID captured from ' + source + ': ' + id);
    }
}

function bytesToString(bytes) {
    try {
        const JString = Java.use('java.lang.String');

        return JString.$new(bytes, 'UTF-8').toString();
    } catch (_) {
        return '';
    }
}

function javaBytesToString(bytes) {
    try {
        return bytesToString(bytes);
    } catch (_) {
        return '';
    }
}

function base64Encode(s) {
    try {
        const Base64 = Java.use('android.util.Base64');
        const JString = Java.use('java.lang.String');

        const bytes = JString.$new(s).getBytes('UTF-8');

        return Base64.encodeToString(bytes, 2); // NO_WRAP
    } catch (_) {
        return null;
    }
}

function urlEncode(s) {
    try {
        const URLEncoder = Java.use('java.net.URLEncoder');
        return URLEncoder.encode(s, 'UTF-8').toString();
    } catch (_) {
        return null;
    }
}

function md5(s) {
    try {
        const MessageDigest = Java.use('java.security.MessageDigest');
        const digest = MessageDigest.getInstance('MD5');
        const bytes = Java.use('java.lang.String').$new(s).getBytes('UTF-8');
        const out = digest.digest(bytes);

        let result = '';

        for (let i = 0; i < out.length; i++) {
            let x = out[i];

            if (x < 0)
                x += 256;

            result += ('0' + x.toString(16)).slice(-2);
        }

        return result;
    } catch (_) {
        return null;
    }
}

function sha1(s) {
    try {
        const MessageDigest = Java.use('java.security.MessageDigest');
        const digest = MessageDigest.getInstance('SHA-1');
        const bytes = Java.use('java.lang.String').$new(s).getBytes('UTF-8');
        const out = digest.digest(bytes);

        let result = '';

        for (let i = 0; i < out.length; i++) {
            let x = out[i];

            if (x < 0)
                x += 256;

            result += ('0' + x.toString(16)).slice(-2);
        }

        return result;
    } catch (_) {
        return null;
    }
}

function sha256(s) {
    try {
        const MessageDigest = Java.use('java.security.MessageDigest');
        const digest = MessageDigest.getInstance('SHA-256');
        const bytes = Java.use('java.lang.String').$new(s).getBytes('UTF-8');
        const out = digest.digest(bytes);

        let result = '';

        for (let i = 0; i < out.length; i++) {
            let x = out[i];

            if (x < 0)
                x += 256;

            result += ('0' + x.toString(16)).slice(-2);
        }

        return result;
    } catch (_) {
        return null;
    }
}

function checkValue(value, location) {
    value = safeString(value);

    if (!value)
        return false;

    let matched = false;

    for (let i = 0; i < advertisingIds.length; i++) {
        const id = advertisingIds[i];

        // 1. Exact plaintext
        if (value.indexOf(id) !== -1) {
            reportMatch(
                location,
                'PLAINTEXT',
                id,
                value
            );
            matched = true;
        }

        // 2. URL encoded
        if (CONFIG.CHECK_URL_ENCODED) {
            const encoded = urlEncode(id);

            if (encoded && encoded !== id &&
                value.indexOf(encoded) !== -1) {

                reportMatch(
                    location,
                    'URL_ENCODED',
                    id,
                    value
                );

                matched = true;
            }
        }

        // 3. Base64
        if (CONFIG.CHECK_BASE64) {
            const encoded64 = base64Encode(id);

            if (encoded64 &&
                encoded64.length > 8 &&
                value.indexOf(encoded64) !== -1) {

                reportMatch(
                    location,
                    'BASE64',
                    id,
                    value
                );

                matched = true;
            }
        }

        // 4. Common hashes
        if (CONFIG.CHECK_HASHES) {
            const hashes = [
                ['MD5', md5(id)],
                ['SHA1', sha1(id)],
                ['SHA256', sha256(id)]
            ];

            for (let j = 0; j < hashes.length; j++) {
                const algorithm = hashes[j][0];
                const digest = hashes[j][1];

                if (digest &&
                    value.toLowerCase().indexOf(digest.toLowerCase()) !== -1) {

                    reportMatch(
                        location,
                        algorithm,
                        id,
                        value
                    );

                    matched = true;
                }
            }
        }
    }

    return matched;
}

function reportMatch(location, encoding, id, data) {
    console.log('');
    console.log('============================================================');
    console.log('[AAID EXFILTRATION CANDIDATE]');
    console.log('Location : ' + location);
    console.log('Encoding : ' + encoding);
    console.log('AAID     : ' + id);
    console.log('Data     : ' + truncate(data, CONFIG.MAX_PRINT));
    console.log('============================================================');
    console.log('');
}

/*
 * -------------------------------------------------------------
 * Advertising ID acquisition
 * -------------------------------------------------------------
 */

function hookAdvertisingId() {
    try {
        const AdvertisingIdClient =
            Java.use(
                'com.google.android.gms.ads.identifier.AdvertisingIdClient'
            );

        const getInfo =
            AdvertisingIdClient.getAdvertisingIdInfo;

        if (getInfo) {
            getInfo.implementation = function(context) {
                const result = getInfo.call(this, context);

                try {
                    const id = result.getId();

                    addAdvertisingId(
                        id,
                        'AdvertisingIdClient.getAdvertisingIdInfo()'
                    );
                } catch (e) {
                    warn('Could not read AdvertisingIdClient.Info: ' + e);
                }

                return result;
            };

            log('Hooked AdvertisingIdClient.getAdvertisingIdInfo()');
        }
    } catch (e) {
        log('AdvertisingIdClient not loaded yet: ' + e);
    }
}

/*
 * Also hook Info.getId(), because some apps obtain the Info object
 * and call getId() later.
 */
function hookAdvertisingIdInfo() {
    try {
        const Info =
            Java.use(
                'com.google.android.gms.ads.identifier.AdvertisingIdClient$Info'
            );

        Info.getId.implementation = function() {
            const id = this.getId();

            addAdvertisingId(
                id,
                'AdvertisingIdClient.Info.getId()'
            );

            return id;
        };

        log('Hooked AdvertisingIdClient.Info.getId()');
    } catch (e) {
        // Class may not exist in every app.
    }
}

/*
 * -------------------------------------------------------------
 * java.net.URL / URLConnection
 * -------------------------------------------------------------
 */

function hookURL() {
    try {
        const URL = Java.use('java.net.URL');

        URL.$init.overload('java.lang.String').implementation =
            function(spec) {

                const s = safeString(spec);

                checkValue(
                    s,
                    'java.net.URL constructor'
                );

                return this.$init(s);
            };

        log('Hooked java.net.URL');
    } catch (e) {
        warn('URL hook failed: ' + e);
    }
}

/*
 * -------------------------------------------------------------
 * HttpURLConnection
 *
 * Covers common Java/Kotlin applications using:
 *
 *   URL.openConnection()
 *   HttpURLConnection
 *
 * Concrete Android implementation classes vary by OS/API level,
 * so the hooks below focus on the public API and dynamically
 * instrument returned OutputStreams.
 * -------------------------------------------------------------
 */

function hookHttpURLConnection() {
    try {
        const HUC =
            Java.use('java.net.HttpURLConnection');

        HUC.connect.implementation = function() {
            const url = safeString(this.getURL());

            checkValue(url, 'HttpURLConnection.connect URL');

            if (CONFIG.LOG_ALL_NETWORK)
                log('HttpURLConnection CONNECT ' + url);

            return this.connect();
        };

        HUC.setRequestProperty.overload(
            'java.lang.String',
            'java.lang.String'
        ).implementation = function(name, value) {

            const n = safeString(name);
            const v = safeString(value);

            checkValue(
                n + ': ' + v,
                'HttpURLConnection header'
            );

            return this.setRequestProperty(name, value);
        };

        HUC.addRequestProperty.overload(
            'java.lang.String',
            'java.lang.String'
        ).implementation = function(name, value) {

            const n = safeString(name);
            const v = safeString(value);

            checkValue(
                n + ': ' + v,
                'HttpURLConnection header'
            );

            return this.addRequestProperty(name, value);
        };

        HUC.getOutputStream.implementation = function() {
            const stream = this.getOutputStream();

            try {
                const url = safeString(this.getURL());
                const key = getObjectId(stream);

                outputStreams[key] = {
                    url: url,
                    method: safeString(this.getRequestMethod())
                };

                hookOutputStreamClass(stream);

                if (CONFIG.LOG_ALL_NETWORK)
                    log(
                        'HttpURLConnection OUTPUT ' +
                        safeString(this.getRequestMethod()) +
                        ' ' + url
                    );
            } catch (e) {
                warn('OutputStream tracking failed: ' + e);
            }

            return stream;
        };

        log('Hooked java.net.HttpURLConnection');
    } catch (e) {
        warn('HttpURLConnection hook failed: ' + e);
    }
}

function getObjectId(obj) {
    try {
        const System = Java.use('java.lang.System');
        return String(System.identityHashCode(obj));
    } catch (_) {
        return String(obj);
    }
}

/*
 * Dynamically hook the concrete OutputStream implementation.
 */
const hookedOutputStreamClasses = {};

function hookOutputStreamClass(stream) {
    try {
        const clazz = stream.getClass();
        const className = clazz.getName().toString();

        if (hookedOutputStreamClasses[className])
            return;

        hookedOutputStreamClasses[className] = true;

        const C = Java.use(className);

        if (C.write) {

            try {
                C.write.overload('[B').implementation =
                    function(bytes) {

                        inspectBytes(
                            bytes,
                            'HttpURLConnection POST body'
                        );

                        return this.write(bytes);
                    };
            } catch (_) {}

            try {
                C.write.overload(
                    '[B',
                    'int',
                    'int'
                ).implementation =
                    function(bytes, off, len) {

                        inspectBytes(
                            sliceJavaBytes(bytes, off, len),
                            'HttpURLConnection POST body'
                        );

                        return this.write(bytes, off, len);
                    };
            } catch (_) {}

            try {
                C.write.overload('int').implementation =
                    function(b) {

                        // Single-byte writes are generally not useful
                        // to inspect individually.
                        return this.write(b);
                    };
            } catch (_) {}

            log(
                'Hooked OutputStream: ' +
                className
            );
        }
    } catch (e) {
        warn('Could not hook OutputStream: ' + e);
    }
}

function sliceJavaBytes(bytes, off, len) {
    try {
        const out = Java.array(
            'byte',
            new Array(len).fill(0)
        );

        for (let i = 0; i < len; i++)
            out[i] = bytes[off + i];

        return out;
    } catch (_) {
        return bytes;
    }
}

function inspectBytes(bytes, location) {
    try {
        const s = javaBytesToString(bytes);

        if (s)
            checkValue(s, location);
    } catch (_) {}
}

/*
 * -------------------------------------------------------------
 * OkHttp
 *
 * Retrofit normally uses an HTTP client underneath it. In the
 * common Retrofit + OkHttp configuration, inspecting OkHttp
 * Request / RequestBody gives much better coverage than trying
 * to hook every Retrofit service method.
 * -------------------------------------------------------------
 */

function hookOkHttp() {
    hookOkHttp3();
    hookOkHttp4();
}

function hookOkHttp3() {
    try {
        const Request =
            Java.use('okhttp3.Request');

        Request.urlString.implementation = function() {
            const url = this.urlString();

            checkValue(
                safeString(url),
                'OkHttp Request URL'
            );

            return url;
        };

        Request.header.overload(
            'java.lang.String'
        ).implementation = function(name) {

            const value = this.header(name);

            checkValue(
                safeString(name) + ': ' + safeString(value),
                'OkHttp Request header'
            );

            return value;
        };

        log('Hooked okhttp3.Request');
    } catch (e) {
        // OkHttp may not be present.
    }

    try {
        const RequestBody =
            Java.use('okhttp3.RequestBody');

        /*
         * RequestBody.writeTo(Buffer) is particularly useful for
         * POST/PUT/PATCH requests.
         *
         * We call the original method first, then inspect the
         * resulting Buffer. This avoids replacing the body.
         */
        RequestBody.writeTo.implementation = function(sink) {

            const result = this.writeTo(sink);

            try {
                const text = sink.clone().readUtf8();

                checkValue(
                    text,
                    'OkHttp RequestBody'
                );
            } catch (_) {}

            return result;
        };

        log('Hooked okhttp3.RequestBody.writeTo()');
    } catch (e) {
        // Abstract RequestBody implementations may make this
        // unavailable on some versions.
    }

    try {
        const RealCall =
            Java.use('okhttp3.RealCall');

        RealCall.execute.implementation = function() {

            try {
                const request = this.request();
                const url = request.urlString();

                checkValue(
                    url,
                    'OkHttp RealCall.execute URL'
                );

                if (CONFIG.LOG_ALL_NETWORK)
                    log('OkHttp EXECUTE ' + url);
            } catch (_) {}

            return this.execute();
        };

        log('Hooked okhttp3.RealCall.execute()');
    } catch (_) {}
}

function hookOkHttp4() {
    /*
     * OkHttp 4 still commonly exposes the okhttp3 package namespace,
     * because the library maintains Java/Kotlin compatibility.
     *
     * Keep this separate so failures do not affect the rest of the
     * script.
     */

    try {
        const RequestBuilder =
            Java.use('okhttp3.Request$Builder');

        RequestBuilder.url.overload(
            'java.lang.String'
        ).implementation = function(url) {

            checkValue(
                safeString(url),
                'OkHttp Request.Builder.url'
            );

            return this.url(url);
        };

        log('Hooked okhttp3.Request$Builder');
    } catch (_) {}
}

/*
 * -------------------------------------------------------------
 * WebView / Cordova
 *
 * Cordova applications commonly execute JS inside WebView.
 *
 * Java-side WebView hooks can reveal:
 *   loadUrl()
 *   evaluateJavascript()
 *   URL interception
 *
 * XHR/fetch payloads may not pass through these methods, so this
 * section is deliberately treated as supplemental coverage.
 * -------------------------------------------------------------
 */

function hookWebView() {
    try {
        const WebView = Java.use('android.webkit.WebView');

        WebView.loadUrl.overload(
            'java.lang.String'
        ).implementation = function(url) {

            checkValue(
                safeString(url),
                'WebView.loadUrl'
            );

            return this.loadUrl(url);
        };

        try {
            WebView.loadUrl.overload(
                'java.lang.String',
                'java.util.Map'
            ).implementation = function(url, headers) {

                checkValue(
                    safeString(url),
                    'WebView.loadUrl headers URL'
                );

                return this.loadUrl(url, headers);
            };
        } catch (_) {}

        try {
            WebView.evaluateJavascript.overload(
                'java.lang.String',
                'android.webkit.ValueCallback'
            ).implementation = function(script, callback) {

                checkValue(
                    safeString(script),
                    'WebView.evaluateJavascript'
                );

                return this.evaluateJavascript(
                    script,
                    callback
                );
            };
        } catch (_) {}

        log('Hooked Android WebView');
    } catch (e) {
        warn('WebView hook failed: ' + e);
    }
}

/*
 * -------------------------------------------------------------
 * Java String / byte[] propagation
 *
 * This is intentionally NOT globally hooked. Hooking every
 * String/byte[] operation causes enormous noise and performance
 * problems.
 *
 * Instead, network sinks above are inspected.
 * -------------------------------------------------------------
 */

/*
 * -------------------------------------------------------------
 * Flutter
 *
 * Flutter networking can bypass Java's HttpURLConnection and
 * OkHttp depending on the library being used.
 *
 * These hooks cover common Java-side Flutter bridge activity,
 * but native/Dart socket traffic requires an additional layer.
 * -------------------------------------------------------------
 */

function hookFlutterBridges() {
    try {
        const MethodChannel =
            Java.use('io.flutter.plugin.common.MethodChannel');

        MethodChannel.invokeMethod.overload(
            'java.lang.String',
            'java.lang.Object'
        ).implementation = function(method, arguments) {

            const m = safeString(method);
            const a = safeString(arguments);

            checkValue(
                m + ' ' + a,
                'Flutter MethodChannel'
            );

            return this.invokeMethod(
                method,
                arguments
            );
        };

        log('Hooked Flutter MethodChannel');
    } catch (_) {
        // Flutter not present or class not loaded.
    }
}

/*
 * -------------------------------------------------------------
 * Native socket layer
 *
 * This catches lower-level native send/write calls used by
 * libraries that do not use Java HTTP APIs.
 *
 * It is deliberately limited to inspecting printable payloads.
 * -------------------------------------------------------------
 */

function hookNativeNetworking() {
    try {
        const sendPtr = Module.findExportByName(
            null,
            'send'
        );

        if (sendPtr) {
            Interceptor.attach(sendPtr, {
                onEnter(args) {
                    try {
                        const buf = args[1];
                        const len = args[2].toInt32();

                        if (len <= 0 || len > CONFIG.MAX_BODY)
                            return;

                        const data =
                            Memory.readUtf8String(
                                buf,
                                Math.min(len, CONFIG.MAX_PRINT)
                            );

                        if (data)
                            checkValue(
                                data,
                                'native send()'
                            );
                    } catch (_) {}
                }
            });

            log('Hooked native send()');
        }
    } catch (e) {
        warn('native send hook failed: ' + e);
    }

    try {
        const writePtr = Module.findExportByName(
            null,
            'write'
        );

        if (writePtr) {
            Interceptor.attach(writePtr, {
                onEnter(args) {
                    try {
                        const fd = args[0].toInt32();
                        const buf = args[1];
                        const len = args[2].toInt32();

                        if (fd < 0 ||
                            len <= 0 ||
                            len > CONFIG.MAX_BODY)
                            return;

                        const data =
                            Memory.readUtf8String(
                                buf,
                                Math.min(len, CONFIG.MAX_PRINT)
                            );

                        if (data)
                            checkValue(
                                data,
                                'native write()'
                            );
                    } catch (_) {}
                }
            });

            log('Hooked native write()');
        }
    } catch (e) {
        warn('native write hook failed: ' + e);
    }
}

/*
 * -------------------------------------------------------------
 * Generic loaded-class discovery
 *
 * Some apps use shaded/relocated OkHttp. We look for classes
 * whose names contain okhttp, retrofit, or advertising identifier.
 * -------------------------------------------------------------
 */

function enumerateInterestingClasses() {
    try {
        Java.enumerateLoadedClasses({
            onMatch(name) {
                const lower = name.toLowerCase();

                if (
                    lower.indexOf('okhttp') !== -1 ||
                    lower.indexOf('retrofit') !== -1 ||
                    lower.indexOf('advertisingid') !== -1
                ) {
                    log('Loaded relevant class: ' + name);
                }
            },

            onComplete() {}
        });
    } catch (_) {}
}

/*
 * -------------------------------------------------------------
 * Main
 * -------------------------------------------------------------
 */

Java.perform(function() {

    log('Starting Advertising ID exfiltration detector');
    log('PID: ' + Process.id);

    hookAdvertisingId();
    hookAdvertisingIdInfo();

    hookURL();
    hookHttpURLConnection();

    hookOkHttp();

    hookWebView();
    hookFlutterBridges();

    enumerateInterestingClasses();

    /*
     * Native hooks are useful for Flutter/native networking but
     * can generate considerably more events.
     *
     * Enable if Java-level hooks do not reveal the traffic.
     */
    hookNativeNetworking();

    log('Hooks installed');
    log('Trigger the app flows that obtain/use the Advertising ID');
});
