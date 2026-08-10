"""
Shared credential/config loader for scripts under scripts/.

Credentials are resolved in this order (first match wins):
  1. Environment variable named "<SECTION>_<KEY>" (uppercased),
     e.g. CISCO_DEFAULT_USERNAME, CISCO_LOCAL_PASSWORD.
  2. A local "credentials.ini" file (gitignored) placed next to this
     file, with one [section] per credential set:

         [cisco_default]
         username = svc-cisco-automation
         password = ...
         enable_password = ...

         [cisco_local]
         username = araung
         password = ...
         enable_password = ...

  3. The `default` argument passed to get_cred(), if any.

The "cisco_default" section holds the primary/service-account
credentials used for automation. The "cisco_local" section (and
optional numbered siblings "cisco_local2", "cisco_local3", ...) are
fallback accounts (e.g. personal/local device accounts) used when the
service account fails to authenticate.
"""

import configparser
import os

_CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
_CRED_FILE = os.path.join(_CONFIG_DIR, "credentials.ini")

_parser = None


def _load_parser():
    global _parser
    if _parser is None:
        _parser = configparser.ConfigParser()
        if os.path.exists(_CRED_FILE):
            _parser.read(_CRED_FILE)
    return _parser


def get_cred(section, key, default=None):
    env_var = f"{section.upper()}_{key.upper()}"
    if os.environ.get(env_var):
        return os.environ[env_var]

    parser = _load_parser()
    if parser.has_option(section, key):
        value = parser.get(section, key)
        if value:
            return value

    return default
