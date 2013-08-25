// Generated on 2013-06-26 using generator-webapp 0.2.4
'use strict';

var child_process = require('child_process');
var fs = require('fs');
var path = require('path');
var proxy = require('proxy-middleware');

var LIVERELOAD_PORT = 35729;
var lrSnippet = require('connect-livereload')({port: LIVERELOAD_PORT});
var mountFolder = function (connect, dir) {
    return connect.static(require('path').resolve(dir));
};

var addHeaders = function(headers) {
    return function(req, res, next) {
        for (var key in headers) {
            if (req.url == "/relay.html" && key == "X-Frame-Options")
                continue;
            res.setHeader(key, headers[key]);
        }
        next();
    };
}

var proxyPath = function(route, port) {
    return proxy({
        route: route,
        protocol: 'http:',
        hostname: '127.0.0.1',
        port: port,
        pathname: '/'
    });
};

var KDC_PROXY_PORT = 5001;

// # Globbing
// for performance reasons we're only matching one level down:
// 'test/spec/{,*/}*.js'
// use this if you want to recursively match all subfolders:
// 'test/spec/**/*.js'

module.exports = function (grunt) {
    // load all grunt tasks
    require('matchdep').filterDev('grunt-*').forEach(grunt.loadNpmTasks);

    // configurable paths
    var yeomanConfig = {
        app: 'app',
        dist: 'out'
    };

    /*
    var appConfig = {
        realm: 'ATHENA.MIT.EDU',
        server: 'https://roost-api.mit.edu',
        serverPrincipal: 'HTTP/roost-api.mit.edu',
        webathena: 'https://webathena.mit.edu'
    };
    if (grunt.option('realm'))
        appConfig.server = grunt.option('realm');
    if (grunt.option('server'))
        appConfig.server = grunt.option('server');
    if (grunt.option('server-principal'))
        appConfig.serverPrincipal = grunt.option('server-principal');
    if (grunt.option('webathena'))
        appConfig.webathena = grunt.option('webathena');
    */

    // Declare non-HSTS headers here, so they can be emitted both to
    // .htaccess and in the dev server.
    var csp = "default-src 'self'; " +
        "style-src 'self' https://fonts.googleapis.com; " +
        "font-src https://themes.googleusercontent.com; " +
        "object-src 'none'";
    var headers = {
        // Standard header; Chrome 25+
        'Content-Security-Policy': csp,
        // Firefox and IE.
        'X-Content-Security-Policy': csp,
        // Safari 6+ and Chrome < 25
        'X-WebKit-CSP': csp,
        // XSS filters can sometimes be abused to selectively disable
        // script tags. With inline script disabled, it's probably
        // fine, but it's configure them to hard-fail anyway.
        'X-XSS-Protection': '1; mode=block',
        // Disallow iframes to do a bit against click-jacking.
        'X-Frame-Options': 'deny',
        // Disable content sniffing, per Tangled Web. Though it's not
        // a huge deal as we're completely static.
        'X-Content-Options': 'nosniff'
    };

    grunt.initConfig({
//        app: appConfig,
        yeoman: yeomanConfig,
        watch: {
            options: {
                nospawn: true
            },
            livereload: {
                options: {
                    livereload: LIVERELOAD_PORT
                },
                files: [
                    '<%= yeoman.app %>/*.html',
                    '{.tmp,<%= yeoman.app %>}/styles/{,*/}*.css',
                    '{.tmp,<%= yeoman.app %>}/scripts/{,*/}*.js',
                    '<%= yeoman.app %>/images/{,*/}*.{png,jpg,jpeg,gif,webp,svg}'
                ]
            }
        },
        connect: {
            options: {
                port: 5000,
                // change this to '0.0.0.0' to access the server from outside
                hostname: 'localhost'
            },
            livereload: {
                options: {
                    middleware: function (connect) {
                        return [
                            // livereload and CSP don't play well.
                            // lrSnippet,
                            addHeaders(headers),
                            proxyPath('/kdc', KDC_PROXY_PORT),
                            mountFolder(connect, '.tmp'),
                            mountFolder(connect, yeomanConfig.app + '/dev-overlay'),
                            mountFolder(connect, yeomanConfig.app)
                        ];
                    }
                }
            },
            test: {
                options: {
                    middleware: function (connect) {
                        return [
                            mountFolder(connect, '.tmp'),
                            mountFolder(connect, 'test'),
                            mountFolder(connect, yeomanConfig.app + '/dev-overlay'),
                            mountFolder(connect, yeomanConfig.app)
                        ];
                    }
                }
            },
            dist: {
                options: {
                    middleware: function (connect) {
                        return [
                            addHeaders(headers),
                            proxyPath('/kdc', KDC_PROXY_PORT),
                            mountFolder(connect, yeomanConfig.dist)
                        ];
                    }
                }
            }
        },
        open: {
            server: {
                path: 'http://localhost:<%= connect.options.port %>'
            }
        },
        clean: {
            dist: {
                files: [{
                    dot: true,
                    src: [
                        '.tmp',
                        '<%= yeoman.dist %>/*',
                        '!<%= yeoman.dist %>/.git*'
                    ]
                }]
            },
            server: [
               '.tmp',
               '<%= yeoman.app %>/scripts-src/config.js'
            ]
        },
        mocha: {
            all: {
                options: {
                    run: true,
                    urls: ['http://localhost:<%= connect.options.port %>/index.html']
                }
            }
        },
        // not used since Uglify task does concat,
        // but still available if needed
        /*concat: {
            dist: {}
        },*/
        // not enabled since usemin task does concat and uglify
        // check index.html to edit your build targets
        // enable this task if you prefer defining your build targets here
        uglify: {
            options: { preserveComments: 'some' }
        },
        rev: {
            dist: {
                files: {
                    src: [
                        '<%= yeoman.dist %>/scripts/{,*/}*.js',
                        '<%= yeoman.dist %>/styles/{,*/}*.css',
                        '<%= yeoman.dist %>/images/{,*/}*.{png,jpg,jpeg,gif,webp}',
                        '<%= yeoman.dist %>/styles/fonts/*'
                    ]
                }
            }
        },
        useminPrepare: {
            options: {
                dest: '<%= yeoman.dist %>'
            },
            html: '<%= yeoman.app %>/*.html'
        },
        usemin: {
            options: {
                dirs: ['<%= yeoman.dist %>']
            },
            html: ['<%= yeoman.dist %>/{,*/}*.html'],
            css: ['<%= yeoman.dist %>/styles/{,*/}*.css']
        },
        // Put files not handled in other tasks here
        copy: {
            dist: {
                files: [{
                    expand: true,
                    dot: true,
                    cwd: '<%= yeoman.app %>',
                    dest: '<%= yeoman.dist %>',
                    src: [
                        '*.{ico,png,txt}',
                        '.htaccess',
                        'images/{,*/}*.{webp,gif}',
                        'images/{,*/}*.{png,jpg,jpeg}',
                        'images/{,*/}*.svg',
                        'styles/{,*/}*.css',
			// Anything to be compiled goes in scripts-src/. This
			// directory is things that are already minified.
                        'scripts/{,*/}*.js',
                        '*.html',
                        'kdc.fcgi'
                    ]
                }, {
                    expand: true,
                    cwd: '.tmp/images',
                    dest: '<%= yeoman.dist %>/images',
                    src: [
                        'generated/*'
                    ]
                }]
            }
        }
    });

    grunt.registerTask('config', function() {
/*
        grunt.file.write(yeomanConfig.app + '/scripts-src/config.js',
                         '"use strict"\n' +
                         'var CONFIG = ' + JSON.stringify(appConfig) + ';');
*/

        var htaccess = grunt.file.read(yeomanConfig.app + '/htaccess-header');
        htaccess += '\n';
        for (var key in headers) {
            htaccess += 'Header add ' + key + ' "' +
                headers[key].replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
            if (key == 'X-WebKit-CSP')
                htaccess += ' env=!broken_safari';
            htaccess += '\n';
        }
        htaccess += grunt.file.read(yeomanConfig.app + '/htaccess-footer');
        grunt.file.write(yeomanConfig.app + '/.htaccess', htaccess);
    });

    grunt.registerTask('kdc-proxy', function() {
        grunt.log.writeln('Spawning KDC proxy')
        var kdc = child_process.spawn(
            path.join(yeomanConfig.app, '../kdc/kdc.py'),
            ['127.0.0.1:' + String(KDC_PROXY_PORT)],
            {env: process.env, stdio: 'inherit'});
        kdc.on('exit', function(code) {
            grunt.log.writeln('KDC proxy exitted with code ' + code);
        });
        process.on('exit', function() {
            grunt.log.writeln('Killing KDC proxy')
            kdc.kill();
        });

        // Sleep for 100ms for the proxy to be ready.
        setTimeout(this.async(), 100);
    });

    grunt.registerTask('server', function (target) {
        if (target === 'dist') {
            return grunt.task.run(['build', 'open', 'kdc-proxy', 'connect:dist:keepalive']);
        }

        grunt.task.run([
            'clean:server',
            'config',
            'kdc-proxy',
            'connect:livereload',
            'open',
            'watch'
        ]);
    });

    grunt.registerTask('test', [
        'clean:server',
        'config',
        'connect:test',
        'mocha'
    ]);

    grunt.registerTask('fix-perms', function() {
        // Because grunt is lame.
        fs.chmodSync(path.join(yeomanConfig.dist, 'kdc.fcgi'), '755');
    });

    grunt.registerTask('export-webathena', function() {
        grunt.file.copy(path.join(yeomanConfig.dist, 'scripts/webathena.js'),
                        'dist/webathena.js');
    });

    grunt.registerTask('build', [
        'clean:dist',
        'config',
        'useminPrepare',
        'concat',
        'uglify',
        'copy:dist',
        'fix-perms',
        'export-webathena',
        'rev',
        'usemin'
    ]);

    grunt.registerTask('default', [
        'test',
        'build'
    ]);
};
