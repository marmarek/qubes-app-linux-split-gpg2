#!/usr/bin/python3
# split-gpg2.py
# Copyright (C) 2014 HW42 <hw42@ipsumj.de>
# Copyright (C) 2019 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Part of split-gpg2.
#
# This implements the server part. See README for details.

# pylint: disable=too-many-lines

import asyncio
import configparser
import enum

import logging
import os
import pathlib
import re
import signal
import socket
import string
import subprocess
import sys
import time
from typing import Optional, Dict, Callable, Awaitable, Tuple, Pattern, List
import xdg.BaseDirectory

# from assuan.h
ASSUAN_LINELENGTH = 1002

known_eddsa_curves = { b'Ed25519', b'Ed448' }

known_safeecdh_curves = { b'Curve25519', b'X448' }

known_other_curves = {
    b'NIST P-256',
    b'NIST P-384',
    b'NIST P-521',
    b'brainpoolP256r1',
    b'brainpoolP384r1',
    b'brainpoolP512r1',
    b'secp256k1',
}

class GPGErrorCode:
    # see gpg-error.h
    SOURCE_SHIFT = 24
    SOURCE_GPGAGENT = 4
    ERR_USER_1 = 1024
    ERR_NO_SCDAEMON = 119
    ERR_ASS_UNKNOWN_CMD = 275

    UnknownIPCCommand = SOURCE_GPGAGENT << SOURCE_SHIFT | ERR_ASS_UNKNOWN_CMD
    NoSCDaemon = SOURCE_GPGAGENT << SOURCE_SHIFT | ERR_NO_SCDAEMON


class StartFailed(Exception):
    pass


class GetSocketPathFailed(Exception):
    pass


class ProtocolError(Exception):
    pass


class Filtered(Exception):
    gpg_message = "Command filtered by split-gpg2."
    code = (GPGErrorCode.SOURCE_GPGAGENT << GPGErrorCode.SOURCE_SHIFT |
            GPGErrorCode.ERR_USER_1)


@enum.unique
class OptionHandlingType(enum.Enum):
    # pylint: disable=invalid-name
    fake = 1
    verify = 2
    override = 3


class HashAlgo:
    def __init__(self, name: str, length: int) -> None:
        self.name = name
        self.len = length

class BaseKeyInfo(object):
    fingerprint: Optional[bytes]
    keygrip: Optional[bytes]
    capabilities: bytes
    __slots__ = ('fingerprint', 'keygrip', 'capabilities')
    def __init__(self, capabilities: bytes) -> None:
        self.fingerprint = None
        self.keygrip = None
        self.capabilities = capabilities

class SubKeyInfo(BaseKeyInfo):
    key: 'KeyInfo'
    __slots__ = ('key',)
    def __init__(self, capabilities: bytes, key: 'KeyInfo'):
        super().__init__(capabilities)
        self.key = key

class KeyInfo(BaseKeyInfo):
    subkeys: List[SubKeyInfo]
    first_uid: Optional[bytes]
    __slots__ = ('subkeys', 'first_uid')
    def __init__(self, capabilities: bytes):
        super().__init__(capabilities)
        self.first_uid = None
        self.subkeys = []

@enum.unique
class ServerState(enum.Enum):
    # pylint: disable=invalid-name
    client_command = 1  # waiting for client command
    client_inquire = 2  # waiting for client response for inquire
    agent_response = 3  # waiting for agent response


def extract_args(untrusted_line: bytes, sep: bytes = b' '):
    """Split a line into a command and arguments (if any).

    Returns: tuple(untrusted_cmd, untrusted_args)
    """
    if sep in untrusted_line:
        return untrusted_line.split(sep, 1)
    return untrusted_line, None

# none of our uses allow 0, so do not allow it
_int_re = re.compile(rb'\A[1-9][0-9]*\Z')

def sanitize_int(untrusted_arg: bytes, min_value: int, max_value: int) -> int:
    """
    Convert an untrusted decimal byte string to an integer.  Raises
    :py:class:`Filtered` if the string is not the decimal representation
    of an integer, or if the return value would be smaller than min_value or
    larger than max_value.
    """
    length = len(untrusted_arg)
    if not 1 <= length <= len(str(max_value)):
        raise Filtered # bad length
    if not _int_re.match(untrusted_arg):
        raise Filtered
    res = int(untrusted_arg, 10)
    if not min_value <= res <= max_value:
        raise Filtered
    return res

class GpgServer:
    """
    Protocol class for interacting with remote client connecting to split-gpg2.
    This class contains methods that handle, sanitize, and pass down gpg
    agent protocol messages received from the client. This is also a
    central place keeping the state of given connection.

    Separate protocol (:py:class:`AgentProtocol`) is used to interact with
    local real gpg agent. Its instance is saved in *agent_protocol* attribute.
    """
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    # type hints, enable when python >= 3.6 will be everywhere...
    inquire_commands: Dict[bytes, Callable[[bytes], Awaitable]]
    timer_delay: Dict[str, Optional[int]]
    hash_algos: Dict[int, HashAlgo]
    options: Dict[bytes, Tuple[OptionHandlingType, bytes]]
    commands: Dict[bytes, Callable[[bytes], Awaitable]]
    client_domain: str
    seen_data: bool

    cache_nonce_regex: re.Pattern = re.compile(rb'\A[0-9A-F]{24}\Z')

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, client_domain: str,
                 debug_log: str = None):

        # configuration options:
        self.verbose_notifications = False
        self.timer_delay = self.default_timer_delay()
        #: allow client to generate a new key
        self.allow_keygen = False
        #: signal those Futures when connection is terminated
        self.notify_on_disconnect = set()
        self.log_io_enable = False
        self.gnupghome = None

        self.client_reader = reader
        self.client_writer = writer
        self.client_domain = client_domain
        self.commands = self.default_commands()
        self.options = self.default_options()
        self.hash_algos = self.default_hash_algos()

        self.log = logging.getLogger('splitgpg2.Server')
        self.agent_socket_path = None
        self.agent_reader: Optional[asyncio.StreamReader] = None
        self.agent_writer: Optional[asyncio.StreamWriter] = None

        self.update_keygrip_map()
        self.seen_data = False

        if debug_log:
            handler = logging.FileHandler(debug_log)
            self.log.addHandler(handler)
            self.log.setLevel(logging.DEBUG)
            self.log_io_enable = True

    def _parse_timer_val(self, value, option_name):
        if value == 'no':
            return None
        if value == 'yes':
            return -1
        try:
            int_value = int(value)
            if int_value <= 0:
                raise ValueError(value)
        except ValueError as e:
            self.log.error(
                "Invalid value '%s' for '%s' config option",
                str(e), option_name
            )
            raise
        return int_value

    def _parse_bool_val(self, value, option_name):
        if value == 'no':
            return False
        if value == 'yes':
            return True
        self.log.error(
            "Invalid value '%s' for '%s' config option",
            value, option_name
        )
        raise ValueError(value)

    def load_config(self, config):
        default_autoaccept = config.get('autoaccept', 'no')
        for timer_name in TIMER_NAMES:
            timer_value = config.get(timer_name + '_autoaccept',
                default_autoaccept)
            self.timer_delay[timer_name] = self._parse_timer_val(
                timer_value, 'autoaccept')

        self.verbose_notifications = self._parse_bool_val(
            config.get('verbose_notifications', 'no'), 'verbose_notifications')

        self.allow_keygen = self._parse_bool_val(
            config.get('allow_keygen', 'no'), 'allow_keygen')

        if 'isolated_gnupghome_dirs' in config:
            self.gnupghome = os.path.join(
                config['isolated_gnupghome_dirs'],
                self.client_domain)

        self.gnupghome = config.get('gnupghome', self.gnupghome)

        # warn about unknown options, to easier spot typos, but don't refuse to
        # start, to allow extensibility
        supported_options = (
            'autoaccept',
            'pksign_autoaccept',
            'pkdecrypt_autoaccept',
            'verbose_notifications',
            'allow_keygen',
            'gnupghome',
            'isolated_gnupghome_dirs',
            # handled in main()
            'debug_log',
        )
        for option in config:
            if option not in supported_options:
                self.log.warning('Unsupported config option: %s', option)

    async def run(self):
        await self.connect_agent()
        try:
            while not self.client_reader.at_eof():
                await self.handle_command()
        finally:
            # close connection to the real gpg agent too
            self.agent_writer.close()

    def log_io(self, prefix, untrusted_msg):
        if not self.log_io_enable:
            return
        allowed = string.printable.\
            replace('\t', '').\
            replace('\n', '').\
            replace('\r', '').\
            replace('\f', '').\
            replace('\v', '')
        allowed = allowed.encode('ascii')
        self.log.warning('%s: %s', prefix, ''.join(
            chr(c) if c in allowed else '.'
            for c in untrusted_msg.strip()))

    def homedir_opts(self):
        if self.gnupghome:
            return ('--homedir', self.gnupghome)
        return ()

    async def connect_agent(self):
        try:
            subprocess.check_call(
                ['gpgconf', *self.homedir_opts(), '--launch', 'gpg-agent'])
        except subprocess.CalledProcessError as e:
            raise StartFailed from e

        dirs = subprocess.check_output(
            ['gpgconf', *self.homedir_opts(), '--list-dirs'])
        if self.allow_keygen:
            socket_field = b'agent-socket:'
        else:
            socket_field = b'agent-extra-socket:'
        # search for agent-socket:/run/user/1000/gnupg/S.gpg-agent
        agent_socket_path = [d.split(b':', 1)[1] for d in dirs.splitlines()
                             if d.startswith(socket_field)][0]
        self.agent_socket_path = agent_socket_path.decode()

        self.agent_reader, self.agent_writer = await asyncio.open_unix_connection(
                path=self.agent_socket_path)

        if self.verbose_notifications:
            self.notify('connected')

        # wait for agent hello
        await self.handle_agent_response()

    def close(self, reason, log_level=logging.ERROR):
        self.log.log(log_level, '%s; Closing!', reason)
        # pylint: disable=protected-access
        self.client_reader._transport.close()
        self.client_writer.close()
        self.agent_writer.close()

    def close_on_filtered_error(self, e):
        self.notify('command filtered out')
        self.client_write('ERR {} {}\n'.format(e.code, e.gpg_message).encode())
        # Break handling since we aren't sure that clients handle the error
        # correctly. This makes the filtering easier to implement and
        # we ensure that a client does not wrongly assumes that a command
        # was successful while is was indeed filtered out.
        self.close('command filtered out')

    async def handle_command(self):
        try:
            untrusted_line = await self.read_one_line_from_client()
            if not untrusted_line:
                # EOF
                return

            untrusted_cmd, untrusted_args = extract_args(untrusted_line)
            try:
                command = self.commands[untrusted_cmd]
            except KeyError as e:
                raise Filtered from e
            await command(untrusted_args=untrusted_args)
        except Filtered as e:
            self.log.exception(e)
            self.close_on_filtered_error(e)
        except:  # pylint: disable=bare-except
            self.log.exception('Error processing command')
            self.close('error')

    async def handle_inquire(self, inquire_commands):
        untrusted_line = await self.read_one_line_from_client()
        try:
            untrusted_cmd, untrusted_args = extract_args(untrusted_line)
            try:
                inquire_command = inquire_commands[untrusted_cmd]
            except KeyError as e:
                raise Filtered from e
            return await inquire_command(untrusted_args=untrusted_args)
        except Filtered as e:
            self.close_on_filtered_error(e)
        except:  # pylint: disable=bare-except
            self.log.exception('Error processing inquire')
            self.close('error')

    def default_commands(self):
        return {
            b'RESET': self.command_RESET,
            b'OPTION': self.command_OPTION,
            b'AGENT_ID': self.command_AGENT_ID,
            b'HAVEKEY': self.command_HAVEKEY,
            b'KEYINFO': self.command_KEYINFO,
            b'GENKEY': self.command_GENKEY,
            b'SIGKEY': self.command_SIGKEY,
            b'SETKEY': self.command_SETKEY,
            b'SETKEYDESC': self.command_SETKEYDESC,
            b'PKDECRYPT': self.command_PKDECRYPT,
            b'SETHASH': self.command_SETHASH,
            b'PKSIGN': self.command_PKSIGN,
            b'GETINFO': self.command_GETINFO,
            b'BYE': self.command_BYE,
            b'SCD': self.command_SCD
        }

    @staticmethod
    def default_options():
        return {
            b'ttyname': (OptionHandlingType.fake, b'OK'),
            b'ttytype': (OptionHandlingType.fake, b'OK'),
            b'display': (OptionHandlingType.override, b':0'),
            b'lc-ctype': (OptionHandlingType.fake, b'OK'),
            b'lc-messages': (OptionHandlingType.fake, b'OK'),
            b'putenv': (OptionHandlingType.fake, b'OK'),
            b'allow-pinentry-notify': (OptionHandlingType.verify, None),
            b'agent-awareness': (OptionHandlingType.verify, b'2.1.0')
        }

    @staticmethod
    def default_timer_delay():
        return {
            'PKSIGN': None,     # always query for signing
            'PKDECRYPT': 300    # 5 min
        }

    @staticmethod
    def default_hash_algos():
        return {
            2: HashAlgo('sha1', 40),
            3: HashAlgo('rmd160', 40),
            8: HashAlgo('sha256', 64),
            9: HashAlgo('sha384', 96),
            10: HashAlgo('sha512', 128),
            11: HashAlgo('sha224', 56),
        }

    @staticmethod
    def notify(msg):
        # TODO: call into dbus directly
        subprocess.call(['notify-send', 'split-gpg2: {}'.format(msg)])

    def request_timer(self, name):
        now = time.time()
        delay = self.timer_delay[name]
        timestamp_path = self.timestamp_path(name)
        if delay is not None:
            if delay < 0:
                self.notify('command {} automatically allowed'.format(name))
                return
            try:
                mtime = timestamp_path.stat().st_mtime
                if mtime + delay > now:
                    self.notify('command {} automatically allowed'.format(name))
                    return
            except FileNotFoundError:
                pass

        short_msg = "split-gpg2: '{}' wants to execute {}".format(
            self.client_domain, name)
        question = '{}\nDo you want to allow this{}?'.format(
            short_msg,
            'for the next {}s'.format(delay) if delay is not None else '')
        if subprocess.call(['zenity', '--question', '--title', short_msg,
                            '--text', question, '--timeout', '30']) != 0:
            raise Filtered

        self.notify('command {} allowed'.format(name))
        timestamp_path.touch()

    def timestamp_path(self, name) -> pathlib.Path:
        return pathlib.Path('{}_split-gpg2-timestamp_{}_{}'.format(
            self.agent_socket_path, name, self.client_domain))

    def client_write(self, data):
        self.log_io('C <<<', data)
        self.client_writer.write(data)

    async def read_one_line_from_client(self):
        untrusted_line = await self.client_reader.readline()
        untrusted_line = untrusted_line.rstrip(b'\n')
        # pylint: disable=arguments-differ
        if len(untrusted_line) > ASSUAN_LINELENGTH:
            raise Filtered('Line too long, dropping')
        self.log_io('C >>>', untrusted_line)
        return untrusted_line

    async def send_inquire(self, inquire, inquire_commands):
        self.client_write(b'INQUIRE ' + inquire + b'\n')
        self.seen_data = False
        while await self.handle_inquire(inquire_commands):
            pass

    def fake_respond(self, response):
        self.client_write(response + b'\n')

    @staticmethod
    def verify_keygrip_arguments(min_count, max_count, untrusted_args):
        args_regex = re.compile(rb'\A[0-9A-F]{40}( [0-9A-F]{40}){%d,%d}\Z' %
                                (min_count-1, max_count-1))

        if args_regex.match(untrusted_args) is None:
            raise Filtered
        return untrusted_args

    def sanitize_key_desc(self, untrusted_args: bytes) -> bytes:
        untrusted_args = untrusted_args.replace(b'+', b' ')
        untrusted_args = re.sub(
            rb'%[0-9A-F]{2}',
            lambda m: bytes([int(m.group(0)[1:].decode('ascii'), 16)]),
            untrusted_args
        )
        allowed_ascii = list(range(0x20, 0x7e)) + [0x0a]
        args = "Message from '{}':\n{}".format(
            self.client_domain,
            ''.join((chr(c) if c in allowed_ascii else '.')
                    for c in untrusted_args)
        )
        return args.replace('%', '%25').\
            replace('+', '%2B').\
            replace('\n', '%0A').\
            replace(' ', '+').\
            encode('ascii')

    async def command_RESET(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            raise Filtered
        await self.send_agent_command(b'RESET', None)

    async def command_OPTION(self, untrusted_args: Optional[bytes]):
        if not untrusted_args:
            raise Filtered

        untrusted_name, untrusted_value = extract_args(untrusted_args, b'=')
        try:
            action, opts = self.options[untrusted_name]
            name = untrusted_name
        except KeyError as e:
            raise Filtered from e

        if action == OptionHandlingType.override:
            if opts is not None:
                option_arg = b'%s=%s' % (name, opts)
            else:
                option_arg = name
        elif action == OptionHandlingType.verify:
            if callable(opts):
                verified = opts(untrusted_value=untrusted_value)
            elif isinstance(opts, Pattern):
                verified = (opts.match(untrusted_value) is not None)
            else:
                verified = (untrusted_value == opts)
            if not verified:
                raise Filtered
            value = untrusted_value

            if value is not None:
                option_arg = b'%s=%s' % (name, value)
            else:
                option_arg = name

        elif action == OptionHandlingType.fake:
            self.fake_respond(opts)
            return

        else:
            raise Filtered

        await self.send_agent_command(b'OPTION', option_arg)

    async def command_AGENT_ID(self, untrusted_args: Optional[bytes]):
        # pylint: disable=unused-argument
        self.fake_respond(
            b'ERR %d unknown IPC command' % GPGErrorCode.UnknownIPCCommand)

    async def command_HAVEKEY(self, untrusted_args: Optional[bytes]):
        # upper keygrip limit is arbitary
        if untrusted_args.startswith(b'--list'):
            if b'=' in untrusted_args:
                # 1000 is the default value used by gpg2
                limit = sanitize_int(untrusted_args[len(b'--list='):], 1, 1000)
                args = b'--list=%d' % limit
            else:
                if untrusted_args != b'--list':
                    raise Filtered
                args = b'--list'
        else:
            args = self.verify_keygrip_arguments(1, 200, untrusted_args)
        await self.send_agent_command(b'HAVEKEY', args)

    async def command_KEYINFO(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.send_agent_command(b'KEYINFO', args)

    async def command_GENKEY(self, untrusted_args: Optional[bytes]):
        if not self.allow_keygen:
            raise Filtered
        args = []
        if untrusted_args is not None:
            cache_nonce_seen = no_protection = False
            for untrusted_arg in untrusted_args.split(b' '):
                if untrusted_arg in (b'--no-protection', b'--inq-passwd'):
                    # allow --no-protection and --inq-passwd
                    # non-empty passphrase responses will be rejected later
                    if cache_nonce_seen:
                        # option must come before cache_nonce
                        raise Filtered
                    if no_protection:
                        # option must only be used once
                        raise Filtered
                    no_protection = True
                    args.append(untrusted_arg)
                elif untrusted_arg.startswith(b'--timestamp='):
                    # Allow --timestamp=, but set creation time to now, no
                    # matter what the client passed.
                    if cache_nonce_seen:
                        # option must come before cache_nonce
                        raise Filtered
                    args.append(time.strftime('--timestamp=%Y%m%dT%H%M%S',
                                              time.gmtime()).encode('ascii'))
                elif self.cache_nonce_regex.match(untrusted_arg) \
                        and not cache_nonce_seen:
                    # Do not passthrough the cache nonce. Otherwise the client
                    # can set the passphrase of another unlocked key.
                    cache_nonce_seen = True
                else:
                    raise Filtered

        args = b' '.join(args)
        await self.send_agent_command(b'GENKEY', args)

    async def command_SIGKEY(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.send_agent_command(b'SIGKEY', args)
        await self.setkeydesc(args)

    async def command_SETKEY(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.send_agent_command(b'SETKEY', args)
        await self.setkeydesc(args)

    async def setkeydesc(self, keygrip):
        info = self.keygrip_map.get(keygrip)
        if info is None:
            self.update_keygrip_map()
            info = self.keygrip_map.get(keygrip)

        if info is None:
            if not self.allow_keygen:
                raise Filtered
            desc = b'Keygrip: ' + keygrip
        else:
            if isinstance(info, SubKeyInfo):
                key = info.key
                subkey_desc = b'\nSubkey Fingerprint: %s' % info.fingerprint
            else:
                key = info
                subkey_desc = b''

            desc = b'UID: %s\nFingerprint: %s%s' % (
                    key.first_uid.split(b'\n')[0],
                    key.fingerprint,
                    subkey_desc)

        self.agent_write(b'SETKEYDESC %s\n' % self.percent_plus_escape(desc))

        untrusted_line = await self.agent_reader.readline()
        untrusted_line = untrusted_line.rstrip(b'\n')
        self.log_io('A >>>', untrusted_line)
        if untrusted_line != b'OK':
            raise ProtocolError('SETKEYDESC failed')

    @staticmethod
    def estream_unescape(escaped):
        """Undo es_write_sanitized()"""

        char_map = { b'\\': b'\\',
                     b'n': b'\n',
                     b'r': b'\r',
                     b'f': b'\f',
                     b'v': b'\v',
                     b'b': b'\b',
                     b'0': b'\0'}
        def map_back(match):
            char = match.group(1)
            if char in char_map:
                return char_map[char]
            return bytes([int(char[1:2], 16)])


        return re.sub(rb'\\(\\|n|r|f|v|b|0|x[0-9a-f]{2})', map_back, escaped)

    @staticmethod
    def percent_plus_escape(to_escape):
        unescaped_ascii = [
            c for c in range(0x20, 0x7e)
            if c not in list(b'+"% ')]
        def esc(char):
            if char in unescaped_ascii:
                return bytes([char])
            if char == ord(' '):
                return b'+'
            return b'%%%02x' % char
        return b''.join(esc(c) for c in to_escape)

    def update_keygrip_map(self) -> None:
        out = subprocess.check_output([
            'gpg', *self.homedir_opts(), '--list-secret-keys', '--with-colons'
        ])
        keys: List[BaseKeyInfo] = []
        key: Optional[KeyInfo] = None
        subkey: Optional[SubKeyInfo] = None
        for line in out.split(b"\n"):
            fields = line.split(b":")
            if fields[0] in [b"sec", b"ssb", b""]:
                subkey = None
            if fields[0] in [b"sec", b""] and key is not None:
                keys.append(key)
            if fields[0] == b"sec":
                key = KeyInfo(fields[11])
            elif fields[0] == b"ssb":
                assert key is not None, 'subkey before primary key?'
                subkey = SubKeyInfo(fields[11], key)
                key.subkeys.append(subkey)
            elif fields[0] == b"fpr":
                if subkey is None:
                    key.fingerprint = fields[9]
                else:
                    subkey.fingerprint = fields[9]
            elif fields[0] == b"grp":
                if subkey is None:
                    key.keygrip = fields[9]
                else:
                    subkey.keygrip = fields[9]
            elif fields[0] == b"uid":
                assert key is not None, 'uid before primary key?'
                if key.first_uid is None:
                    key.first_uid = self.estream_unescape(fields[9])
        new_keygrip_map: Dict[bytes, BaseKeyInfo] = {}
        for key in keys:
            if key.keygrip is not None:
                new_keygrip_map[key.keygrip] = key
            for subkey in key.subkeys:
                if subkey.keygrip is not None:
                    new_keygrip_map[subkey.keygrip] = subkey
        self.keygrip_map = new_keygrip_map

    async def command_SETKEYDESC(self, untrusted_args: Optional[bytes]):
        # Fake a positive respose. We always send a SETKEYDESC after
        # SETKEY/SIGKEY.
        # pylint: disable=unused-argument
        self.fake_respond(b'OK')

    async def command_PKDECRYPT(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            raise Filtered
        self.request_timer('PKDECRYPT')
        await self.send_agent_command(b'PKDECRYPT', None)

    async def command_SETHASH(self, untrusted_args: Optional[bytes]):
        untrusted_alg, untrusted_hash = untrusted_args.split(b' ', 1)
        # OpenPGP uses 1-byte algorithm numbers, so the highest algorithm
        # number possible is 255.
        alg = sanitize_int(untrusted_alg, 2, 255)
        try:
            alg_param = self.hash_algos[alg]
        except KeyError as e:
            raise Filtered from e

        if not untrusted_hash:
            raise Filtered

        hash_regex = re.compile(rb'\A[0-9A-F]{%d}\Z' % alg_param.len)
        if hash_regex.match(untrusted_hash) is None:
            raise Filtered
        hash_value = untrusted_hash

        await self.send_agent_command(
            b'SETHASH', b'%d %s' % (alg, hash_value))

    async def command_PKSIGN(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            if not untrusted_args.startswith(b'-- '):
                raise Filtered
            untrusted_args = untrusted_args[3:]
            if self.cache_nonce_regex.match(untrusted_args) is None:
                raise Filtered
            args = b'-- ' + untrusted_args
        else:
            args = None

        self.request_timer('PKSIGN')

        await self.send_agent_command(b'PKSIGN', args)

    async def command_GETINFO(self, untrusted_args: Optional[bytes]):
        if not untrusted_args in [b'version', b'restricted']:
            raise Filtered
        args = untrusted_args

        await self.send_agent_command(b'GETINFO', args)

    async def command_BYE(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            raise Filtered
        await self.send_agent_command(b'BYE', None)
        self.close("Client closed connection", logging.INFO)

    async def command_SCD(self, untrusted_args: Optional[bytes]):
        # We don't support smartcard daemon commands, but fake enough that the
        # search for a default key doesn't fail.

        if untrusted_args not in (b'SERIALNO openpgp', b'SERIALNO'):
            raise Filtered

        self.fake_respond(
            b'ERR %d No SmartCard daemon' % GPGErrorCode.NoSCDaemon)

    def get_inquires_for_command(self, command: bytes) -> Dict[bytes, Callable]:
        if command == b'GENKEY':
            inquires = {
                b'KEYPARAM': self.inquire_KEYPARAM,
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
                b'NEWPASSWD': self.inquire_NEWPASSWD,
            }
            return inquires
        if command == b'PKDECRYPT':
            return {
                b'CIPHERTEXT': self.inquire_CIPHERTEXT,
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
        if command == b'PKSIGN':
            return {
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
        return {}

    async def send_agent_command(self, command: bytes, args: Optional[bytes]):
        """ Sends command to local gpg agent and handle the response """
        expected_inquires = self.get_inquires_for_command(command)
        if args:
            cmd_with_args = command + b' ' + args + b'\n'
        else:
            cmd_with_args = command + b'\n'
        self.agent_write(cmd_with_args)
        while True:
            more_expected = await self.handle_agent_response(
                    expected_inquires=expected_inquires)
            if not more_expected:
                break

    def agent_write(self, data):
        self.log_io('A <<<', data)
        self.agent_writer.write(data)

    async def handle_agent_response(self, expected_inquires=None):
        """ Receive and handle one agent response. Return whether there are
        more expected """
        if expected_inquires is None:
            expected_inquires = {}
        # We generally consider the agent as trusted. But since the client can
        # determine part of the response we handle this here as untrusted.
        untrusted_line = await self.agent_reader.readline()
        untrusted_line = untrusted_line.rstrip(b'\n')
        self.log_io('A >>>', untrusted_line)
        untrusted_res, untrusted_args = extract_args(untrusted_line)
        if untrusted_res in (b'D', b'S'):
            # passthrough to the client
            self.client_write(untrusted_line + b'\n')
            return True
        if untrusted_res in (b'OK', b'ERR'):
            # passthrough to the client and signal command complete
            self.client_write(untrusted_line + b'\n')
            return False
        if untrusted_res == b'INQUIRE':
            if not untrusted_args:
                raise Filtered
            await self.handle_agent_inquire(
                    expected_inquires=expected_inquires,
                    untrusted_args=untrusted_args)
            return True
        raise ProtocolError('unexpected gpg-agent response')

    async def handle_agent_inquire(self, expected_inquires, *, untrusted_args):
        untrusted_inq, untrusted_inq_args = extract_args(untrusted_args)
        try:
            inquire = expected_inquires[untrusted_inq]
        except KeyError as e:
            raise Filtered from e
        await inquire(untrusted_args=untrusted_inq_args)

    # region INQUIRE commands sent from gpg-agent
    #

    async def inquire_NEWPASSWD(self, untrusted_args):
        if untrusted_args is not None:
            raise Filtered('unexpected arguments to NEWPASSWD inquire')
        # This really ought to be forbidden, but it is used by the simplest
        # of creating a key with no passphrase.  Therefore, allow it, but
        # do not allow responding with a non-empty passphrase.
        await self.send_inquire(b'NEWPASSWD', {
            b'END': self.inquire_command_END,
        })

    async def inquire_KEYPARAM(self, untrusted_args):
        if untrusted_args is not None:
            raise Filtered('unexpected arguments to KEYPARAM inquire')
        await self.send_inquire(b'KEYPARAM', {
            b'D': self.inquire_command_D_KEYGEN,
            b'END': self.inquire_command_END,
        })

    async def inquire_PINENTRY_LAUNCHED(self, untrusted_args):
        # This comes from the local agent and shouldn't be controlled by the
        # untrusted client. Additionally the only thing we do with it is to
        # send it back to the client.
        args = untrusted_args

        await self.send_inquire(b'PINENTRY_LAUNCHED ' + args, {
            b'END': self.inquire_command_END,
        })

    async def inquire_CIPHERTEXT(self, untrusted_args):
        """
        Handle a CIPHERTEXT inquiry

        The expected response is an sexp of one of the following forms:

        - (enc-val (ecdh (s <s>) (e <e>))) for ECDH
        - (enc-val (rsa (a <A>))) for RSA
        - (enc-val (elg (a <A>) (b <b>))) for ElGamal
        """
        if untrusted_args is not None:
            raise Filtered('unexpected arguments to CIPHERTEXT inquire')
        await self.send_inquire(b'CIPHERTEXT', {
            b'D': self.inquire_command_D_CIPHERTEXT,
            b'END': self.inquire_command_END,
        })

    # endregion

    # region INQUIRE responses sent by client back to the agent
    #
    # each function returns whether further responses are expected

    @classmethod
    def check_letter_sexp(cls, start_string: bytes, untrusted_sexp,
                          expected_ty: type) -> None:
        """
        Check that ``untrusted_sexp`` is a list of length 2 that starts with
        ``start_string`` and has a second element of type ``expected_ty``.
        Returns the second element.
        """
        if not isinstance(untrusted_sexp, list) or len(untrusted_sexp) != 2:
            raise Filtered
        untrusted_first, untrusted_last = untrusted_sexp
        if untrusted_first != start_string:
            raise ValueError('Invalid head of sexp')
        if not isinstance(untrusted_last, expected_ty):
            raise ValueError('Invalid type of sexp tail')
        return untrusted_last

    def inquire_command_D_CIPHERTEXT(self, *, untrusted_args: bytes):
        def check_mpi_list(names: List[bytes], *, untrusted_sexp: List[object]):
            """
            Check that the elements in ``untrusted_sexp`` are length-2
            lists.  The first element in each list is expected to be
            equal to the corresponding element in ``names``, and the
            second to be of type bytes.  If any of these do not hold,
            raise :py:class:`Filtered`.
            """
            if len(names) != len(untrusted_sexp):
                raise Filtered
            for (name, untrusted_value) in zip(names, untrusted_sexp):
                self.check_letter_sexp(name, untrusted_value, bytes)

        def validate_ciphertext_sexp(*, untrusted_sexp):
            """
            Check that the ``untrusted_sexp`` is a valid offer of a ciphertext
            for decryption.
            """
            untrusted_sexp = self.check_letter_sexp(
                    b'enc-val', untrusted_sexp, list)
            if len(untrusted_sexp) < 2:
                raise ValueError('No MPIs found')
            untrusted_alg = untrusted_sexp[0]
            if untrusted_alg == b'ecdh':
                check_mpi_list((b's', b'e'), untrusted_sexp=untrusted_sexp[1:])
            elif untrusted_alg == b'rsa':
                check_mpi_list((b'a',), untrusted_sexp=untrusted_sexp[1:])
            elif untrusted_alg == b'elg':
                check_mpi_list((b'a', b'b'), untrusted_sexp=untrusted_sexp[1:])
            else:
                raise ValueError("Unknown encryption algorithm")

        return self.inquire_command_D(validate_ciphertext_sexp,
                                      untrusted_args=untrusted_args)

    def inquire_command_D_KEYGEN(self, *, untrusted_args: bytes):
        def validate_bits_len(untrusted_sexp):
            untrusted_bits = self.check_letter_sexp(
                    b'nbits', untrusted_sexp, bytes)
            sanitize_int(untrusted_bits, 1024, 4096)

        def check_curve_flags(untrusted_curve, untrusted_flags):
            # Non-Edwards curves are easy; check those first
            if untrusted_curve in known_other_curves:
                if untrusted_flags != [b'nocomp']:
                    raise ValueError('Invalid flags for non-Edwards curve')
                return

            # Now the Edwards curves
            if untrusted_curve in known_eddsa_curves:
                allowed_flags = (b'eddsa', b'comp')
            elif untrusted_curve in known_safeecdh_curves:
                allowed_flags = (b'comp', b'djb-tweak')
            else:
                raise ValueError('Unknown elliptic curve')
            if len(untrusted_flags) > 2:
                raise ValueError('Too many flags for Edwards curve')
            if b'comp' not in untrusted_flags:
                raise ValueError('Edwards curve keys must be compressed')
            for untrusted_flag in untrusted_flags:
                if untrusted_flag not in allowed_flags:
                    raise ValueError('Forbidden flag sent')

        def validate_keygen_sexp(*, untrusted_sexp):
            """
            Check that the ``untrusted_sexp`` is a valid set of key generation
            parameters.
            """
            untrusted_sexp = self.check_letter_sexp(
                    b'genkey', untrusted_sexp, list)
            if len(untrusted_sexp) < 2:
                raise ValueError('No key parameters')
            untrusted_alg = untrusted_sexp[0]
            if untrusted_alg == b'ecc':
                if len(untrusted_sexp) != 3:
                    raise ValueError('invalid elliptic curve parameters')
                untrusted_curve = self.check_letter_sexp(
                        b'curve', untrusted_sexp[1], bytes)
                untrusted_flags = untrusted_sexp[2]
                if not isinstance(untrusted_flags, list):
                    raise ValueError('Flags must be a list')
                if len(untrusted_flags) < 2 or untrusted_flags[0] != b'flags':
                    raise ValueError(
                            "Key generation flags must begin with b'flags'")
                check_curve_flags(untrusted_curve, untrusted_flags[1:])
            elif untrusted_alg in (b'rsa', b'openpgp-elg'):
                if len(untrusted_sexp) != 2:
                    raise ValueError('invalid ElGamel or RSA parameters')
                validate_bits_len(untrusted_sexp[1])
            elif untrusted_alg == b'dsa':
                if (len(untrusted_sexp) != 3 or
                    untrusted_sexp[2] != [b'qbits', b'256']):
                    raise ValueError('invalid DSA parameters')
                validate_bits_len(untrusted_sexp[1])

        return self.inquire_command_D(validate_keygen_sexp,
                                      untrusted_args=untrusted_args)

    async def inquire_command_D(self, validate_sexp, *, untrusted_args):
        # We parse and then reserialize the sexpr. Currently we assume that the
        # sexpr fits in one assuan line. This line length also implicitly
        # limits the sexpr sizes.

        if self.seen_data:
            raise Filtered
        try:
            untrusted_sexp = self.parse_sexpr(self.unescape_D(untrusted_args))
            validate_sexp(untrusted_sexp=untrusted_sexp)
        except ValueError as e:
            raise Filtered from e
        else:
            args = untrusted_sexp

        self.agent_write(b'D ' + self.escape_D(self.serialize_sexpr(args)) + b'\n')
        self.seen_data = True
        return True

    @staticmethod
    def unescape_D(untrusted_arg):
        return re.sub(
            rb'%[0-9A-F]{2}',
            lambda m: bytes([int(m.group(0)[1:], 16)]),
            untrusted_arg
        )

    @staticmethod
    def escape_D(data):
        # Like gpg we only escape those chars that are really necessary. Since
        # the data normally contains binary data it's likely that gpg-agent's
        # parser works fine with strange chars, so it doesn't makes much sense
        # to be more protective here.
        return data.replace(b'%', b'%25').\
                    replace(b'\r', b'%0d').\
                    replace(b'\n', b'%0a')


    # This parser is only good enough to parse the sexpr gpg generates. It does
    # *not* implement http://people.csail.mit.edu/rivest/Sexp.txt fully. Since
    # we send the reserialized form this should be safe.

    @classmethod
    def parse_sexpr(cls, untrusted_arg: bytes):
        # pylint: disable=unidiomatic-typecheck
        if type(untrusted_arg) is not bytes:
            raise TypeError("invalid type in parse_sexpr")
        if len(untrusted_arg) == 0:
            raise ValueError("no sexpr")
        sexpr, rest = cls._parse_sexpr(untrusted_arg, 0)
        if len(rest) != 0:
            raise ValueError("garbage at end of sexpr")
        if len(sexpr) != 1:
            raise ValueError("sexpr top level shold have exactly one element")
        if not isinstance(sexpr[0], list):
            # We assume this in serialize_sexpr and at least for gpg this seems
            # to be true.
            raise ValueError("sexpr top level shold be a list")
        return sexpr[0]

    @classmethod
    def _parse_sexpr(cls, untrusted_arg, nesting):
        if len(untrusted_arg) == 0:
            if nesting > 0:
                raise ValueError("missing closing parenthesis")
            return ([], b'')
        if untrusted_arg[0] == ord(')'):
            if nesting == 0:
                return ([], untrusted_arg)
            if nesting > 20:
                # This limit is arbitrary. The motivation is to avoid problems
                # if gpg-agent would recurse too much based on sexpr nesting
                # **and** would jump the guard page (for example through a big
                # stack allocation). This is borderline too paranoid, but for
                # now we accepted it.
                raise ValueError("sexpr has too big nesting depth")
            return ([], untrusted_arg[1:].lstrip(b' '))

        if untrusted_arg[0] in range(0x30, 0x40):
            length_s, rest = untrusted_arg.split(b':', 1)
            length = sanitize_int(length_s, 1, len(rest))
            value, rest = rest[0:length], rest[length:]
        elif untrusted_arg[0] == ord('('):
            value, rest = cls._parse_sexpr(untrusted_arg[1:], nesting + 1)
        else:
            match = re.match(rb'\A([0-9a-zA-Z-_]+) ?(.*)\Z', untrusted_arg)
            if match is None:
                raise ValueError("Invalid literal")
            value, rest = match.group(1), match.group(2)

        rest_parsed, new_rest = cls._parse_sexpr(rest, nesting)
        return ([value] + rest_parsed, new_rest)

    @classmethod
    def serialize_sexpr(cls, sexpr):
        if not isinstance(sexpr, list):
            raise ValueError("serialize_sexpr expects a list")

        def serialize_item(item):
            if isinstance(item, list):
                return b'(' + b''.join(serialize_item(j) for j in item) + b')'
            if isinstance(item, bytes):
                bytes_item = bytes(item)
                return b'%i:%s' % (len(bytes_item), bytes_item)
            raise ValueError("expected a list or bytes inside an sexpr")

        return b'(' + b''.join(serialize_item(i) for i in sexpr) + b')'

    async def inquire_command_END(self, *, untrusted_args):
        if untrusted_args is not None:
            raise Filtered('unexpected arguments to END')
        self.agent_write(b'END\n')
        return False

    # endregion


TIMER_NAMES = (
    'PKSIGN',
    'PKDECRYPT',
)

def open_stdinout_connection(*, loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader = asyncio.StreamReader(loop=loop)
    loop.run_until_complete(loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader, loop=loop),
        sys.stdin.buffer))

    write_transport, write_protocol = loop.run_until_complete(
            loop.connect_write_pipe(
                lambda: asyncio.streams.FlowControlMixin(loop),
                sys.stdout.buffer))
    writer = asyncio.StreamWriter(write_transport, write_protocol, None, loop)

    return reader, writer


def load_config_files(client_domain):
    config_dirs = ['/etc', xdg.BaseDirectory.xdg_config_home + '/qubes-split-gpg2']

    config = configparser.ConfigParser()
    config.read([os.path.join(d, 'qubes-split-gpg2.conf') for d in config_dirs])
    # 'DEFAULTS' section is special, values there serve as defaults
    # for other sections
    section = 'client:' + client_domain
    if config.has_section(section):
        return config[section]
    return config['DEFAULT']


def main():
    os.umask(0o0077)
    client_domain = os.environ['QREXEC_REMOTE_DOMAIN']
    config = load_config_files(client_domain)

    loop = asyncio.get_event_loop()
    reader, writer = open_stdinout_connection()
    server = GpgServer(reader, writer, client_domain,
        debug_log=config.get('debug_log'))

    try:
        server.load_config(config)
    except ValueError:
        print("Error in a config file, aborting", file=sys.stderr)
        sys.exit(2)

    connection_terminated = loop.create_future()
    server.notify_on_disconnect.add(connection_terminated)
    loop.run_until_complete(server.run())
