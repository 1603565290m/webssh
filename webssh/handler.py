import io
import json
import logging
import socket
import struct
import threading
import traceback
import weakref
import paramiko
import tornado.web
import requests
import sys

from tornado.ioloop import IOLoop
from tornado.util import basestring_type
from webssh.worker import Worker, recycle_worker, workers
from tornado.web import HTTPError
from tornado.options import options
from webssh.policy import user_auth, jwt_encode, authenticated
from webssh.conf import cmdb_api, cmdb_headers
from webssh.conf import delay as DELAY

try:
    from concurrent.futures import Future
except ImportError:
    from tornado.concurrent import Future

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


def parse_encoding(data):
    for line in data.split('\n'):
        s = line.split('=')[-1]
        if s:
            return s.strip('"').split('.')[-1]


class MixinHandler(object):

    def get_real_client_addr(self):
        ip = self.request.headers.get('X-Real-Ip')
        port = self.request.headers.get('X-Real-Port')

        if ip is None and port is None:
            return

        try:
            port = int(port)
        except (TypeError, ValueError):
            pass
        else:
            if ip:  # does not validate ip and port here
                return (ip, port)

        logging.warning('Bad nginx configuration.')
        return False


class MixinRequestHandler(tornado.web.RequestHandler):

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", options.allow_origin)
        self.set_header("Access-Control-Allow-Headers", options.allow_headers)
        self.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.set_header("Request-Id", self.settings['request_id'])

    def check_xsrf_cookie(self):
        token = (self.get_argument("_xsrf", None) or
                 self.request.headers.get("X-Xsrftoken") or
                 self.request.headers.get("X-Csrftoken"))
        if not token:
            raise HTTPError(403, "'_xsrf' argument missing from POST")
        _, token, _ = self._decode_xsrf_token(token)
        _, expected_token, _ = self._get_raw_xsrf_token()
        if not token:
            raise HTTPError(403, "'_xsrf' argument has invalid format")

    def is_ajax(self):
        if "application/json" in self.request.headers._as_list["Content-Type"][0]:
            return True
        return False

    def _request_summary(self):
        return "[{0}] [{1}] [{2}] [request-id:{3}]".format(
            self.request.method, self.request.uri,
            self.request.remote_ip, self.settings['request_id']
        )


class IndexHandler(MixinHandler, MixinRequestHandler):

    def initialize(self, loop, policy, host_keys_settings):
        self.loop = loop
        self.policy = policy
        self.host_keys_settings = host_keys_settings

    def get_argument(self, name, default=object, strip=True):
        """Returns the value of the argument with the given name.

        If default is not provided, the argument is considered to be
        required, and we raise a `MissingArgumentError` if it is missing.

        If the argument appears in the url more than once, we return the
        last value.

        The returned value is always unicode.
        """
        if hasattr(self.request, "body_json"):
            return self.request.body_json[name]

        return self._get_argument(name, default, self.request.arguments, strip)

    def get_privatekey(self):
        try:
            data = self.request.files.get('privatekey')[0]['body']

            return data.decode('utf-8')
        except Exception:
            data = None
        if not data:
            try:
                data = self.request.body_json["privatekey"]
                if sys.version_info > (2,):
                    return data
            except Exception:
                return

    @classmethod
    def get_specific_pkey(cls, pkeycls, privatekey, password):
        logging.info('Trying {0}'.format(pkeycls.__name__,))
        try:
            pkey = pkeycls.from_private_key(io.StringIO(privatekey),
                                            password=password)
        except paramiko.PasswordRequiredException:
            raise ValueError('Need password to decrypt the private key.')
        except paramiko.SSHException:
            pass
        else:
            return pkey

    @classmethod
    def get_pkey_obj(cls, privatekey, password):
        password = password.encode('utf-8') if password else None

        pkey = cls.get_specific_pkey(paramiko.RSAKey, privatekey, password)\
            or cls.get_specific_pkey(paramiko.DSSKey, privatekey, password)\
            or cls.get_specific_pkey(paramiko.ECDSAKey, privatekey, password)\
            or cls.get_specific_pkey(paramiko.Ed25519Key, privatekey,
                                     password)
        if not pkey:
            raise ValueError('Not a valid private key file or '
                             'wrong password for decrypting the private key')
        return pkey

    def get_port(self):
        value = self.get_value('port')
        try:
            port = int(value)
        except ValueError:
            port = 0

        if 0 < port < 65536:
            return port

        raise ValueError('Invalid port {0}, Request-ID:{1}'.format(value, self.settings['request_id']))

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise ValueError('Empty {}, Request-ID:{0}'.format(name, self.settings['request_id']))
        return value

    def get_args(self):
        hostname = self.get_value('hostname')
        port = self.get_port()
        username = self.get_value('username')
        password = self.get_argument('password')
        privatekey = self.get_privatekey()
        pkey = self.get_pkey_obj(privatekey, password) if privatekey else None
        if pkey:
            args = (hostname, port, username, password, pkey)
        else:
            args = (hostname, port, username, password)
        logging.info('host info: {0}, Request-ID: {1}'.format(args, self.settings['request_id']))
        return args

    def get_client_addr(self):
        return self.get_real_client_addr() or self.request.connection.stream.\
            socket.getpeername()

    def get_default_encoding(self, ssh):
        try:
            _, stdout, _ = ssh.exec_command('locale')
        except paramiko.SSHException:
            result = None
        else:
            data = stdout.read().decode()
            result = parse_encoding(data)

        return result if result else 'utf-8'

    def ssh_connect(self):
        ssh = paramiko.SSHClient()
        ssh._system_host_keys = self.host_keys_settings['system_host_keys']
        ssh._host_keys = self.host_keys_settings['host_keys']
        ssh._host_keys_filename = self.host_keys_settings['host_keys_filename']
        ssh.set_missing_host_key_policy(self.policy)

        if self.is_ajax():
            try:
                self.get_host_info()
            except Exception as e:
                raise ValueError('for cmdb get host error: {0}, Request-ID: {1}'.format(e, self.settings['request_id']))

        args = self.get_args()
        dst_addr = (args[0], args[1])
        logging.info('Connecting to {}:{}, Request-ID: {}'.format(dst_addr[0], dst_addr[1], self.settings['request_id']))

        try:
            ssh.connect(*args, timeout=6)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}, Request-ID: {}'.format(dst_addr[0], dst_addr[1], self.settings['request_id']))
        except paramiko.BadAuthenticationType:
            raise ValueError('SSH authentication failed. Request-ID: {}'.format(self.settings['request_id']))
        except paramiko.BadHostKeyException:
            raise ValueError('Bad host key. Request-ID: {}'.format(self.settings['request_id']))

        chan = ssh.invoke_shell(term='xterm')
        chan.setblocking(0)
        worker = Worker(self.loop, ssh, chan, dst_addr)
        worker.src_addr = self.get_client_addr()
        worker.encoding = self.get_default_encoding(ssh)
        return worker

    def ssh_connect_wrapped(self, future):
        try:
            worker = self.ssh_connect()
        except Exception as exc:
            logging.error(traceback.format_exc())
            future.set_exception(exc)
        else:
            future.set_result(worker)

    def options(self, *args, **kwargs):
        self.write('success')

    def get(self):
        self.render('index.html')

    # def is_ajax(self):
    #     if "application/json" in self.request.headers._as_list["Content-Type"][0]:
    #         return True
    #     return False

    def get_host_info(self):
        """
        cmdb api result: {"code":0,"msg":"","data":{"hostname":"192.168.1.2","port":22,"username":"root",
                    "password":"password","privatekey":null}}
        :return:
        """
        url = cmdb_api
        logging.info('for cmdb get host, cmdb url: {0}, Request-ID: {1}'.format(url, self.settings['request_id']))
        param = self.request.body.decode("utf-8")
        param = json.loads(param)
        result = requests.post(url=url, data=param, headers=cmdb_headers, timeout=3)
        logging.info('request cmdb status: {}, data: {}, Request-ID: {}'.format(result.status_code, result.text, self.settings['request_id']))
        json_data = result.json()
        data = json_data["data"]
        self.request.body_json = data

    @tornado.gen.coroutine
    @authenticated
    def post(self):
        worker_id = None
        status = None
        encoding = None

        future = Future()
        t = threading.Thread(target=self.ssh_connect_wrapped, args=(future,))
        t.setDaemon(True)
        t.start()

        try:
            worker = yield future
        except Exception as exc:
            status = str(exc)
        else:
            worker_id = worker.id
            logging.info('worker id: {0}, Request-ID: {1}'.format(worker_id, self.settings['request_id']))
            workers[worker_id] = worker
            self.loop.call_later(DELAY, recycle_worker, worker)
            encoding = worker.encoding

        self.write(dict(id=worker_id, status=status, encoding=encoding))


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def initialize(self, loop):
        self.loop = loop
        self.worker_ref = None

    def check_origin(self, origin):
        return True

    def get_client_addr(self):
        return self.get_real_client_addr() or self.stream.socket.getpeername()

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))
        worker = workers.get(self.get_argument('id'))
        if worker and worker.src_addr[0] == self.src_addr[0]:
            workers.pop(worker.id)
            self.set_nodelay(True)
            worker.set_handler(self)
            self.worker_ref = weakref.ref(worker)
            self.loop.add_handler(worker.fd, worker, IOLoop.READ)
        else:
            self.close(reason='Websocket authentication failed.')

    def on_message(self, message):
        logging.debug('{!r} from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        try:
            msg = json.loads(message)
        except JSONDecodeError:
            return

        if not isinstance(msg, dict):
            return

        resize = msg.get('resize')
        if resize and len(resize) == 2:
            try:
                worker.chan.resize_pty(*resize)
            except (TypeError, struct.error, paramiko.SSHException):
                pass

        data = msg.get('data')
        if data and isinstance(data, basestring_type):
            worker.data_to_dst.append(data)
            worker.on_write()

    def on_close(self):
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            if self.close_reason is None:
                self.close_reason = 'client disconnected'
            worker.close(reason=self.close_reason)


class AuthXsrfHandler(MixinHandler, MixinRequestHandler):

    def initialize(self, loop):
        self.loop = loop

    def options(self, *args, **kwargs):
        self.write('success')

    def post(self, *args, **kwargs):
        if self.is_ajax():
            param = self.request.body.decode("utf-8")
            param = json.loads(param)
            logging.info('Auth info: {0}, Request-ID: {1}'.format(param, self.settings['request_id']))
            if user_auth(data=param):
                logging.info('Auth successful, Request-ID: {}'.format(self.settings['request_id']))
                encoded = jwt_encode(data=param)
                logging.debug('Token: {0}, Request-ID: {1}'.format(encoded, self.settings['request_id']))
                self.write(dict(code=0, status='success', data='{0}'.format(encoded)))
            else:
                logging.info('Auth Failed, Request-ID: {}'.format(self.settings['request_id']))
                self.write(dict(code=1, status='username or password is error', data=''))
        else:
            logging.error('request type is error, Request-ID: {}'.format(self.settings['request_id']))
            self.write(dict(code=2, status='request type error', data=''))
