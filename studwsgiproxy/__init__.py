# -*- encoding: utf-8 -*-

import atexit
import BaseHTTPServer
import hashlib
import hmac
import os
import shutil
import socket
import sys
from distutils.spawn import find_executable
from tempfile import mkstemp
from werkzeug.serving import make_server

from gridproxy.util import x509_load_chain_der

from . import hkdf

def make_hmac_key():
    salt = "ATOdV2Z9R5FVjYGmlhHjOttx2Fn4fWVOlcRCE9fIfCA=".decode("base64")
    return hkdf.genkey(os.urandom(32), 32, "pilot", salt)

def start_stud(exe, front_port, back_port, hmac_key, capath, keycertfile):
    ppid = os.getpid()
    pid = os.fork()
    if pid > 0: 
        return pid
    try:
        MAXFD = os.sysconf("SC_OPEN_MAX")
    except:
        MAXFD = 256
    os.closerange(0, MAXFD)

    cmd = [exe, "--backend", "[127.0.0.1]:%d" % back_port,
           "--frontend", "[*]:%d" % front_port,
           "--verify-depth", "10", "--verify-proxy", "--verify-require",
           "--inject-chain", "--ca-path", capath,
           "--hmac-key", hmac_key.encode("hex"),
           keycertfile]

    try:
        os.execvp(cmd[0], cmd)
        raise RuntimeError("execvp failed for cmd: " + repr(cmd))
    except Exception, exc:
        sys.stderr = open("/dev/tty", "w")
        sys.stderr.write("Failed to start stud: " + str(exc)+"\n")
        sys.stderr.write("Command line was:\n")
        sys.stderr.write(" ".join(cmd) + "\n")
        sys.stderr.flush()
        os.kill(ppid, 15)
        sys.exit(1)

def get_stud_executable(exe):
    if exe is not None:
        return exe

    path = os.pathsep.join([os.path.dirname(__file__),
                            os.path.dirname(__file__) + "/../src/stud", "./src/stud", "../src/stud",
                            os.environ["PATH"]])
    return find_executable("stud", path)

def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("localhost", 0))
    port = s.getsockname()[1]
    s.close()
    return port

class StudProcessor(object):
    def __init__(self, app, key):
        self.app = app
        self.key = key

    def error(self, code, environ, start_response, extra_message=None):
        responses = BaseHTTPServer.BaseHTTPRequestHandler.responses[code]
        short_response = responses[0]
        long_response = "%d %s\n\n%s\n" % (code, responses[0], responses[1])
        if extra_message is not None:
            long_response += "\n"
            long_response += extra_message
            
        start_response('%d %s' % (code, short_response),
                       [("content-type", "text/plain"),
                        ("content-length", str(len(long_response)))])
        return long_response

    def __call__(self, environ, start_response):
        for k in ("HTTP_STUD_SIGNATURE", "HTTP_SSL_PEER_CHAIN",
                  "HTTP_X_FORWARDED_FOR"):
            if k not in environ:
                return self.error(401, environ, start_response)
        sig = environ.pop("HTTP_STUD_SIGNATURE")
        chain = environ.pop("HTTP_SSL_PEER_CHAIN")
        xff = environ.pop("HTTP_X_FORWARDED_FOR")
        signed_part = "SSL-Peer-Chain: %s\r\nX-Forwarded-For: %s\r\n" % (chain, xff)
        if hmac.HMAC(self.key, signed_part, hashlib.sha256).digest() != sig.decode("base64"):
            return self.error(401, environ, start_response)
        environ['x509_client_stack'] = x509_load_chain_der(chain.decode("base64"))
        environ['x509_client_cert'] = environ['x509_client_stack'][0]
        environ['REMOTE_ADDR'] = xff
        return self.app(environ, start_response)

def remove_keycertfile(filename):
    try:
        os.unlink(filename)
    except OSError:
        pass

def run_simple(hostname, port, application, use_reloader=False,
               use_debugger=False, use_evalex=True,
               extra_files=None, reloader_interval=1, threaded=False,
               processes=1, request_handler=None, static_files=None,
               passthrough_errors=False,
               ssl_certificate="/etc/grid-security/hostcert.pem",
               ssl_key="/etc/grid-security/hostkey.pem",
               ssl_ca_path="/etc/grid-security/certificates",
               backend_port=None, stud_executable=None
               ):
    """Start an application using wsgiref and with an optional reloader.  This
    wraps `wsgiref` to fix the wrong default reporting of the multithreaded
    WSGI variable and adds optional multithreading and fork support.

    :param hostname: The host for the application.  eg: ``'localhost'``
    :param port: The port for the server.  eg: ``8080``
    :param application: the WSGI application to execute
    :param use_reloader: should the server automatically restart the python
                         process if modules were changed?
    :param use_debugger: should the werkzeug debugging system be used?
    :param use_evalex: should the exception evaluation feature be enabled?
    :param extra_files: a list of files the reloader should watch
                        additionally to the modules.  For example configuration
                        files.
    :param reloader_interval: the interval for the reloader in seconds.
    :param threaded: should the process handle each request in a separate
                     thread?
    :param processes: number of processes to spawn.
    :param request_handler: optional parameter that can be used to replace
                            the default one.  You can use this to replace it
                            with a different
                            :class:`~BaseHTTPServer.BaseHTTPRequestHandler`
                            subclass.
    :param static_files: a dict of paths for static files.  This works exactly
                         like :class:`SharedDataMiddleware`, it's actually
                         just wrapping the application in that middleware before
                         serving.
    :param passthrough_errors: set this to `True` to disable the error catching.
                               This means that the server will die on errors but
                               it can be useful to hook debuggers in (pdb etc.)
    :param ssl_certificate: path to the host SSL certificate. Default
                            is /etc/grid-security/hostcert.pem                           
    :param ssl_key: path to the host SSL key. Default is
                    /etc/grid-security/hostkey.pem
    :param ssl_ca_path: path to the accepted CA certificates
                        directory. Default is /etc/grid-security/certificates
    :param backend_port: port for plain HTTP backend. Will be chosen
                         automatically if not specified.
    :param stud_executable: path to stud executable. If not specified
                            will search for stud executable in
                            standard package locations and $PATH.
    """
    if use_debugger:
        from werkzeug.debug import DebuggedApplication
        application = DebuggedApplication(application, use_evalex)
    if static_files:
        from werkzeug.wsgi import SharedDataMiddleware
        application = SharedDataMiddleware(application, static_files)

    hmac_key = make_hmac_key()
    if backend_port is None:
        backend_port = find_free_port()

    stud_executable = get_stud_executable(stud_executable)
    if not stud_executable:
        raise RuntimeError("Can't find stud executable. Please specify correct path in stud_executable")

    fd, keycertfile = mkstemp()
    f = os.fdopen(fd, "wb")
    shutil.copyfileobj(open(ssl_certificate, "rb"), f)
    shutil.copyfileobj(open(ssl_key, "rb"), f)
    f.close()
    atexit.register(remove_keycertfile, keycertfile)

    stud_pid = start_stud(stud_executable, port, backend_port, hmac_key, ssl_ca_path, keycertfile)
    atexit.register(os.kill, stud_pid, 15)

    from werkzeug._internal import _log
    display_hostname = hostname != '*' and hostname or 'localhost'
    if ':' in display_hostname:
        display_hostname = '[%s]' % display_hostname    
    _log('info', ' * Frontend running on https://%s:%d/', display_hostname, port)    
    _log('info', ' * Backend running on http://127.0.0.1:%d/', backend_port)
    make_server(hostname, backend_port, application, threaded,
                processes, request_handler,
                passthrough_errors).serve_forever()    
