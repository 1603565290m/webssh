import logging
import os.path
import threading
import paramiko
import jwt
from jwt.exceptions import DecodeError
from webssh.conf import auth
from webssh.conf import secret
from tornado.web import HTTPError


def authenticated(func):

    def wrapper(self, *args, **kwargs):
        if "multipart/form-data" in self.request.headers._as_list["Content-Type"][0]:
            return func(self, *args, **kwargs)

        token = self.request.headers.get("Token")
        logging.debug('Auth Token: {0}, Request-ID: {1}'.format(token, self.settings['request_id']))
        if not token:
            raise HTTPError(403)
        data = jwt_decode(data=token)
        if isinstance(data, bool) or not user_auth(data=data):
            raise HTTPError(403)
        return func(self, *args, **kwargs)
    return wrapper


def user_auth(data):
    if isinstance(data, dict):
        username = data.get('username', None)
        password = data.get('password', None)
        try:
            auth_pass = auth[username]
            if password == auth_pass:
                return True
        except KeyError:
            return False
    return False


def jwt_encode(data):
    return jwt.encode(data, secret, algorithm='HS256')


def jwt_decode(data):
    try:
        decode = jwt.decode(data, secret, algorithm='HS256')
        return decode
    except DecodeError:
        logging.info('jwt decode faild: {0}'.format(data))
    except Exception as e:
        logging.error(e)
    return False


def load_host_keys(path):
    if os.path.exists(path) and os.path.isfile(path):
        return paramiko.hostkeys.HostKeys(filename=path)
    return paramiko.hostkeys.HostKeys()


def get_policy_dictionary():
    dic = {
       k.lower(): v for k, v in vars(paramiko.client).items() if type(v)
       is type and issubclass(v, paramiko.client.MissingHostKeyPolicy)
       and v is not paramiko.client.MissingHostKeyPolicy
    }
    return dic


def get_policy_class(policy):
    origin_policy = policy
    policy = policy.lower()
    if not policy.endswith('policy'):
        policy += 'policy'

    dic = get_policy_dictionary()
    logging.debug(dic)

    try:
        cls = dic[policy]
    except KeyError:
        raise ValueError('Unknown policy {!r}'.format(origin_policy))
    return cls


def check_policy_setting(policy_class, host_keys_settings):
    host_keys = host_keys_settings['host_keys']
    host_keys_filename = host_keys_settings['host_keys_filename']
    system_host_keys = host_keys_settings['system_host_keys']

    if policy_class is paramiko.client.AutoAddPolicy:
        host_keys.save(host_keys_filename)  # for permission test
    elif policy_class is paramiko.client.RejectPolicy:
        if not host_keys and not system_host_keys:
            raise ValueError(
                'Reject policy could not be used without host keys.'
            )


class AutoAddPolicy(paramiko.client.MissingHostKeyPolicy):
    """
    thread-safe AutoAddPolicy
    """
    lock = threading.Lock()

    def is_missing_host_key(self, client, hostname, key):
        k = client._system_host_keys.lookup(hostname) or \
                client._host_keys.lookup(hostname)
        if k is None:
            return True
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return True
        if host_key != key:
            raise paramiko.BadHostKeyException(hostname, key, host_key)

    def missing_host_key(self, client, hostname, key):
        with self.lock:
            if self.is_missing_host_key(client, hostname, key):
                keytype = key.get_name()
                logging.info(
                    'Adding {} host key for {}'.format(keytype, hostname)
                )
                client._host_keys._entries.append(
                    paramiko.hostkeys.HostKeyEntry([hostname], key)
                )

                with open(client._host_keys_filename, 'a') as f:
                    f.write('{} {} {}\n'.format(
                        hostname, keytype, key.get_base64()
                    ))


paramiko.client.AutoAddPolicy = AutoAddPolicy
