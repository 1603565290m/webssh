import logging
import os.path
import sys
import uuid
import random
import string

from tornado.options import define
from webssh.policy import (
    load_host_keys, get_policy_class, check_policy_setting
)
from webssh._version import __version__
import webssh.conf as conf

def print_version(flag):
    if flag:
        print(__version__)
        sys.exit(0)


define('address', default=conf.listen, help='listen address')
define('port', default=conf.port, help='listen port', type=int)
define('debug', default=conf.debug, help='debug mode', type=bool)
define('policy', default='warning',
       help='missing host key policy, reject|autoadd|warning')
define('hostFile', default='', help='User defined host keys file')
define('sysHostFile', default='', help='System wide host keys file')
define('version', type=bool, help='show version information',
       callback=print_version)
define('get_host_info_url', default=conf.cmdb_api, help='get host info')
define('allow_origin', default='*', help='Access-Control-Allow-Origin')
define('allow_headers', default='x-requested-with Origin,Content-Type,X-XSRFToken,X-CSRFToken,Token',
       help='Access-Control-Allow-Headers')

define('log_file_prefix', default=conf.log_file_prefix)
define('log_rotate_mode', default='time')
define('log_rotate_when', default='D')
define('log_rotate_interval', default=1)

base_dir = os.path.dirname(__file__)


def get_request_id():
    request_id = ''.join(random.sample(string.digits + string.ascii_letters, 32))
    return request_id


def get_app_settings(options):
    settings = dict(
        template_path=os.path.join(base_dir, 'templates'),
        static_path=os.path.join(base_dir, 'static'),
        cookie_secret=uuid.uuid4().hex,
        debug=options.debug,
        request_id=get_request_id()
    )
    return settings


def get_host_keys_settings(options):
    if not options.hostFile:
        host_keys_filename = os.path.join(base_dir, 'known_hosts')
    else:
        host_keys_filename = options.hostFile
    host_keys = load_host_keys(host_keys_filename)

    if not options.sysHostFile:
        filename = os.path.expanduser('~/.ssh/known_hosts')
    else:
        filename = options.sysHostFile
    system_host_keys = load_host_keys(filename)

    settings = dict(
        host_keys=host_keys,
        system_host_keys=system_host_keys,
        host_keys_filename=host_keys_filename
    )
    return settings


def get_policy_setting(options, host_keys_settings):
    policy_class = get_policy_class(options.policy)
    logging.info(policy_class.__name__)
    check_policy_setting(policy_class, host_keys_settings)
    return policy_class()
