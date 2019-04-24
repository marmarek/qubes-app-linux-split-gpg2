#!/usr/bin/python3
# split-gpg2.py
# Copyright (C) 2014  HW42 <hw42@ipsumj.de>
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


import asyncio
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
#from asyncio.futures import Future
from typing import Optional, Dict, Callable, Awaitable, Tuple, Pattern

# from assuan.h
ASSUAN_LINELENGTH = 1002


class GPGCode:
    # see gpg-error.h
    SOURCE_SHIFT = 24
    SOURCE_GPGAGENT = 4
    ERR_USER_1 = 1024
    ERR_ASS_UNKNOWN_CMD = 275

    UnknownIPCCommand = SOURCE_GPGAGENT << SOURCE_SHIFT | ERR_ASS_UNKNOWN_CMD


class StartFailed(Exception):
    pass


class GetSocketPathFailed(Exception):
    pass


class ProtocolError(Exception):
    pass


class Filtered(Exception):
    gpg_message = "Command filtered by split-gpg2."
    code = (GPGCode.SOURCE_GPGAGENT << GPGCode.SOURCE_SHIFT |
            GPGCode.ERR_USER_1)


@enum.unique
class OptionType(enum.Enum):
    fake = 1
    verify = 2
    override = 3


class HashAlgo:
    def __init__(self, name: str, lenght: int) -> None:
        self.name = name
        self.len = lenght


@enum.unique
class ServerState(enum.Enum):
    client_command = 1  # waiting for client command
    client_inquire = 2  # waiting for client response for inquire
    agent_response = 3  # waiting for agent response


class ServerProtocol(asyncio.Protocol):
    """
    Protocol class for interacting with remote client connecting to split-gpg2.
    This class contains methods that handle, sanitize, and pass down gpg
    agent protocol messages received from the client. This is also a
    central place keeping the state of given connection.

    Separate protocol (:py:class:`AgentProtocol`) is used to interact with
    local real gpg agent. Its instance is saved in *agent_protocol* attribute.
    """
    # type hints, enable when python >= 3.6 will be everywhere...
    # inquire_commands: Dict[bytes, Callable[[bytes], Awaitable]]
    # timer_delay: Dict[str, Optional[int]]
    # hash_algos: Dict[int, HashAlgo]
    # options: Dict[bytes, Tuple[OptionType, bytes]]
    # commands: Dict[bytes, Callable[[bytes], Awaitable]]
    # client_domain: str
    # agent_protocol: 'AgentProtocol'

    cache_nonce_regex = re.compile(rb'[0-9A-F]{24}')

    def __init__(self, client_domain: str):

        # configuration options:
        self.verbose_notifications = False
        self.timer_delay = self.default_timer_delay()
        #: signal those Futures when connection is terminated
        self.notify_on_disconnect = set()

        self.client_domain = client_domain
        self.commands = self.default_commands()
        self.options = self.default_options()
        self.hash_algos = self.default_hash_algos()
        self.inquire_commands = {}

        self.log = logging.getLogger('splitgpg2.Server')
        self.agent_transport = None
        self.client_transport = None
        self.agent_socket_path = None
        self.agent_protocol = None
        self.untrusted_input_buffer = bytearray()
        # initial state: wait for agent hello
        self.state = ServerState.agent_response
        # asyncio.Future waiting for inquires to the client
        self.inquire_complete = None

    def log_io(self, prefix, untrusted_msg):
        self.log.warning('%s: %s', prefix, ''.join(
            chr(c) if c in string.printable.encode('ascii') else '.'
            for c in untrusted_msg))

    async def connect_agent(self):
        try:
            subprocess.check_call(['gpgconf', '--launch', 'gpg-agent'])
        except subprocess.CalledProcessError:
            raise StartFailed

        dirs = subprocess.check_output(['gpgconf', '--list-dirs'])
        # search for agent-socket:/run/user/1000/gnupg/S.gpg-agent
        agent_socket_path = [d.split(b':', 1)[1] for d in dirs.splitlines()
                             if d.startswith(b'agent-socket:')][0]
        self.agent_socket_path = agent_socket_path.decode()

        loop = asyncio.get_event_loop()
        self.agent_transport, self.agent_protocol = await \
            loop.create_unix_connection(lambda: AgentProtocol(self),
                                        self.agent_socket_path)
        # wait for agent hello
        await self.agent_protocol.agent_responded
        self.state = ServerState.client_command

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.client_transport = transport
        asyncio.ensure_future(self.connect_agent())

    def connection_lost(self, exc: Optional[Exception]) -> None:
        for fut in self.notify_on_disconnect:
            fut.set_result(None)

    def abort(self, reason):
        self.log.error('%s; Aborting!', reason)
        self.client_transport.close()
        self.agent_transport.close()

    async def handle_command(self, *, untrusted_line: bytes):
        # state == ServerState.client_command
        try:
            try:
                untrusted_cmd, untrusted_args = untrusted_line.split(b' ', 1)
            except ValueError:
                untrusted_cmd = untrusted_line
                untrusted_args = None
            try:
                command = self.commands[untrusted_cmd]
            except KeyError:
                raise Filtered
            await command(untrusted_args=untrusted_args)
        except Filtered as e:
            # DEBUG
            self.log.exception('Filtered')

            self.notify('command filtered out')
            self.client_write('ERR {} {}\n'.format(e.code, e.gpg_message).encode())
            # break handling since we aren't sure that clients handle the error
            # correctly. This makes the filtering easier to implement and we ensure
            # that a client does not wrongly assume that a command was successful
            # while is was indeed filtered out.
            self.abort('command filtered out')
        except:
            self.log.exception('Error processing command')
            self.abort('error')

    async def handle_inquire(self, *, untrusted_line: bytes):
        # state == ServerState.client_inquire
        try:
            try:
                untrusted_cmd, untrusted_args = untrusted_line.split(b' ', 1)
            except ValueError:
                untrusted_cmd = untrusted_line
                untrusted_args = None
            try:
                inquire_command = self.inquire_commands[untrusted_cmd]
            except KeyError:
                raise Filtered
            cont = await inquire_command(untrusted_args=untrusted_args)
            if not cont:
                self.inquire_complete.set_result(None)
        except Filtered as e:
            self.notify('command filtered out')
            self.client_write('ERR {} {}\n'.format(e.code, e.gpg_message).encode())
            # break handling since we aren't sure that clients handle the error
            # correctly. This makes the filtering easier to implement and we ensure
            # that a client does not wrongly assume that a command was successful
            # while is was indeed filtered out.
            self.abort('inquire filtered out')
        except:
            self.log.exception('Error processing inquire')
            self.abort('error')

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
            b'BYE': self.command_BYE
        }

    @staticmethod
    def default_options():
        return {
            # should be overriden on startup to reflect sensible values
            b'ttyname': (OptionType.fake, b'OK'),
            b'ttytype': (OptionType.fake, b'OK'),
            b'display': (OptionType.override, b':0'),
            b'lc-ctype': (OptionType.fake, b'OK'),
            b'lc-messages': (OptionType.fake, b'OK'),
            b'putenv': (OptionType.fake, b'OK'),
            b'allow-pinentry-notify': (OptionType.verify, None),
            b'agent-awareness': (OptionType.verify, b'2.1.0')
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
                            '--text', question]) != 0:
            raise Filtered

        self.notify('command {} allowed'.format(name))
        timestamp_path.touch()

    def timestamp_path(self, name) -> pathlib.Path:
        return pathlib.Path('{}_qubes-split-gpg2-timestamp_{}'.format(
            self.agent_socket_path, name))

    def client_write(self, data):
        self.log_io('C <<<', data)
        self.client_transport.write(data)

    def eof_received(self) -> Optional[bool]:
        # close connection to the real gpg agent too
        if self.agent_transport is not None:
            self.agent_transport.write_eof()
        # automatically close the transport
        return False

    def data_received(self, untrusted_data: bytes) -> None:
        if len(self.untrusted_input_buffer) > ASSUAN_LINELENGTH*2:
            self.log.error('Too much data received, dropping')

        self.log_io('C >>>', untrusted_data)

        self.untrusted_input_buffer.extend(untrusted_data)
        if self.state == ServerState.agent_response:
            # now is an agent turn, only buffer the data, but don't act on it
            return

        while b'\n' in self.untrusted_input_buffer:
            # there is a full command buffered
            untrusted_line, untrusted_rest = \
                self.untrusted_input_buffer.split(b'\n', 1)
            self.untrusted_input_buffer = untrusted_rest
            # convert from bytesarray to bytes to be hashable
            untrusted_line = bytes(untrusted_line)
            if self.state == ServerState.client_command:
                asyncio.ensure_future(self.handle_command(
                    untrusted_line=untrusted_line))
            elif self.state == ServerState.client_inquire:
                asyncio.ensure_future(self.handle_inquire(
                    untrusted_line=untrusted_line))

    async def send_inquire(self, inquire, inquire_commands):
        if self.state != ServerState.agent_response:
            raise ProtocolError(
                'invalid server state: INQUIRE not originating from gpg-agent')
        loop = asyncio.get_event_loop()
        self.inquire_complete = loop.create_future()
        self.inquire_commands = inquire_commands
        self.state = ServerState.client_inquire
        self.client_write(b'INQUIRE ' + inquire + b'\n')
        await self.inquire_complete
        self.inquire_commands = {}
        self.state = ServerState.agent_response

    def fake_respond(self, response):
        self.client_write(response + b'\n')

    @staticmethod
    def verify_keygrip_arguments(min_count, max_count, untrusted_args):
        args_regex = re.compile(
            rb'[0-9A-F]{40}( [0-9A-F]{40}){%d,%d}' % (min_count-1, max_count-1))

        if args_regex.fullmatch(untrusted_args) is None:
            raise Filtered
        return untrusted_args

    def sanitize_key_desc(self, untrusted_args: bytes) -> bytes:
        untrusted_args = untrusted_args.replace(b'+', b' ')
        untrusted_args = re.sub(
            rb'%[0-9A-F]{2}',
            lambda m: bytes([int(m.group(0)[1:].decode('ascii'), 16)]),
            untrusted_args,
            flags=re.IGNORECASE
        )
        allowed_ascii = (string.printable + '\x0a').encode('ascii')
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
        if untrusted_args:
            raise Filtered
        await self.agent_protocol.send_command(b'RESET', None)

    async def command_OPTION(self, untrusted_args: Optional[bytes]):
        if not untrusted_args:
            raise Filtered

        try:
            untrusted_name, untrusted_value = untrusted_args.split(b'=', 1)
        except ValueError:
            untrusted_name = untrusted_args
            untrusted_value = None
        try:
            action, opts = self.options[untrusted_name]
            name = untrusted_name
        except KeyError:
            raise Filtered

        if action == OptionType.override:
            if opts:
                option_arg = b'%s=%s' % (name, opts)
            else:
                option_arg = name
        elif action == OptionType.verify:
            if callable(opts):
                verified = opts(untrusted_value=untrusted_value)
            elif isinstance(opts, Pattern):
                verified = (opts.fullmatch(untrusted_value) is not None)
            else:
                verified = (untrusted_value == opts)
            if not verified:
                raise Filtered
            value = untrusted_value

            if value:
                option_arg = b'%s=%s' % (name, value)
            else:
                option_arg = name

        elif action == OptionType.fake:
            self.fake_respond(opts)
            return

        else:
            raise Filtered

        await self.agent_protocol.send_command(b'OPTION', option_arg)

    async def command_AGENT_ID(self, untrusted_args: Optional[bytes]):
        self.fake_respond(
            b'ERR %d unknown IPC command' % GPGCode.UnknownIPCCommand)

    async def command_HAVEKEY(self, untrusted_args: Optional[bytes]):
        # upper keygrip limit is arbitary
        args = self.verify_keygrip_arguments(1, 200, untrusted_args)
        await self.agent_protocol.send_command(b'HAVEKEY', args)

    async def command_KEYINFO(self, untrusted_args: Optional[bytes]):
        # upper keygrip limit is arbitary
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.agent_protocol.send_command(b'KEYINFO', args)

    async def command_GENKEY(self, untrusted_args: Optional[bytes]):
        args = []
        if untrusted_args:
            cache_nonce_added = False
            for untrusted_arg in untrusted_args.split(b' '):
                if untrusted_arg.startswith(b'--'):
                    # according to documentation,
                    # possible options (all related to password):
                    # --inq-passwd
                    # --no-protection
                    # --preset
                    # ignore all of them for now
                    pass
                elif self.cache_nonce_regex.fullmatch(untrusted_arg) \
                        and not cache_nonce_added:
                    args.append(untrusted_arg)
                    cache_nonce_added = True
                else:
                    raise Filtered

        args = b' '.join(args)
        await self.agent_protocol.send_command(b'GENKEY', args)

    async def command_SIGKEY(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.agent_protocol.send_command(b'SIGKEY', args)

    async def command_SETKEY(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.agent_protocol.send_command(b'SETKEY', args)

    async def command_SETKEYDESC(self, untrusted_args: Optional[bytes]):
        # XXX: is there a better way than showing the message
        #      from the untrusted domain
        args = self.sanitize_key_desc(untrusted_args)
        await self.agent_protocol.send_command(b'SETKEYDESC', args)

    async def command_PKDECRYPT(self, untrusted_args: Optional[bytes]):
        if untrusted_args:
            raise Filtered
        self.request_timer('PKDECRYPT')
        await self.agent_protocol.send_command(b'PKDECRYPT', None)

    async def command_SETHASH(self, untrusted_args: Optional[bytes]):
        untrusted_alg, untrusted_hash = untrusted_args.split(b' ', 1)
        try:
            alg = int(untrusted_alg)
            alg_param = self.hash_algos[alg]
        except (KeyError, ValueError):
            raise Filtered

        if not untrusted_hash:
            raise Filtered

        hash_regex = re.compile(rb'[0-9A-F]{%d}' % alg_param.len)
        if hash_regex.fullmatch(untrusted_hash) is None:
            raise Filtered
        hash_value = untrusted_hash

        await self.agent_protocol.send_command(
            b'SETHASH', b'%d %s' % (alg, hash_value))

    async def command_PKSIGN(self, untrusted_args: Optional[bytes]):
        args_regex = re.compile(rb'[0-9A-F]{24}')
        if untrusted_args and args_regex.fullmatch(untrusted_args) is None:
            raise Filtered
        args = untrusted_args

        self.request_timer('PKSIGN')

        await self.agent_protocol.send_command(b'PKSIGN', args)

    async def command_GETINFO(self, untrusted_args: Optional[bytes]):
        if untrusted_args != b'version':
            raise Filtered
        args = untrusted_args

        await self.agent_protocol.send_command(b'GETINFO', args)

    async def command_BYE(self, untrusted_args: Optional[bytes]):
        if untrusted_args:
            raise Filtered
        await self.agent_protocol.send_command(b'BYE', None)


class AgentProtocol(asyncio.Protocol):
    """
    Protocol class for interacting with a local (real) gpg agent.
    """
    # type hints, enable when python >= 3.6 will be everywhere...
    # agent_responded: Optional[Future]
    # expected_inquires: Dict[bytes, Callable]
    # untrusted_agent_response_buffer: bytearray
    # server: ServerProtocol

    def __init__(self, server: ServerProtocol) -> None:
        super(AgentProtocol, self).__init__()
        self.server = server
        self.agent_transport = None
        # We gennerally consider the agent as trusted. But since the client can
        # determine part of the response we handle this here as untrusted.
        self.untrusted_agent_response_buffer = bytearray()
        loop = asyncio.get_event_loop()
        self.agent_responded = loop.create_future()
        self.expected_inquires = {}

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.server.log_io('connected', b'')
        if self.server.verbose_notifications:
            self.server.notify('connected')
        self.agent_transport = transport

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.server.log_io('disconnected', b'')
        if self.server.verbose_notifications:
            self.server.notify('disconnected')
        self.server.client_transport.close()

    def get_inquires_for_command(self, command: bytes) -> Dict[bytes, Callable]:
        if command == b'GENKEY':
            return {
                b'KEYPARAM': self.inquire_KEYPARAM,
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
        elif command == b'PKDECRYPT':
            return {
                b'CIPHERTEXT': self.inquire_CIPHERTEXT,
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
        elif command == b'PKSIGN':
            return {
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
        else:
            return {}

    # was handle_server_response in ruby version
    async def send_command(self, command: bytes, args: Optional[bytes]):
        assert self.server.state == ServerState.client_command
        self.server.state = ServerState.agent_response
        try:
            self.expected_inquires = self.get_inquires_for_command(command)
            loop = asyncio.get_event_loop()
            self.agent_responded = loop.create_future()
            if args:
                cmd_with_args = command + b' ' + args + b'\n'
            else:
                cmd_with_args = command + b'\n'
            self.agent_write(cmd_with_args)
            await self.agent_responded
        finally:
            self.server.state = ServerState.client_command

    def agent_write(self, data):
        self.server.log_io('A <<<', data)
        self.agent_transport.write(data)

    def data_received(self, untrusted_data: bytes) -> None:
        self.server.log_io('A >>>', untrusted_data)
        if self.server.state != ServerState.agent_response:
            self.server.abort('message from gpg-agent at unexpected time')
            return

        self.untrusted_agent_response_buffer.extend(untrusted_data)
        while b'\n' in self.untrusted_agent_response_buffer:
            untrusted_line, untrusted_rest = \
                self.untrusted_agent_response_buffer.split(b'\n', 1)
            self.untrusted_agent_response_buffer = untrusted_rest
            # convert from bytesarray to bytes to be hashable
            untrusted_line = bytes(untrusted_line)
            try:
                self.handle_agent_response(untrusted_line=untrusted_line)
            except Exception as e:
                # propagate exception back to self.send_command
                self.agent_responded.set_exception(e)
                break

    def handle_agent_response(self, *, untrusted_line):
        try:
            untrusted_res, untrusted_args = untrusted_line.split(b' ', 1)
        except ValueError:
            untrusted_res = untrusted_line
            untrusted_args = None
        if untrusted_res in (b'D', b'S'):
            # passthrough to the client
            self.server.client_write(untrusted_line + b'\n')
        elif untrusted_res in (b'OK', b'ERR'):
            # passthrough to the client and signal command complete
            self.server.client_write(untrusted_line + b'\n')
            try:
                self.agent_responded.set_result(None)
            except asyncio.InvalidStateError:
                if untrusted_res == b'ERR':
                    # agent may report multiple errors
                    pass
                raise
        elif untrusted_res == b'INQUIRE':
            if not untrusted_args:
                raise Filtered
            asyncio.ensure_future(self.handle_agent_inquire(
                untrusted_args=untrusted_args))
        else:
            raise ProtocolError('unexpected gpg-agent response')

    async def handle_agent_inquire(self, *, untrusted_args):
        try:
            try:
                untrusted_inq, untrusted_inq_args = untrusted_args.split(b' ', 1)
            except ValueError:
                untrusted_inq = untrusted_args
                untrusted_inq_args = None
            try:
                inquire = self.expected_inquires[untrusted_inq]
            except KeyError:
                raise Filtered
            await inquire(untrusted_args=untrusted_inq_args)
        except Exception as e:
            # propagate exception back to self.send_command
            if not self.agent_responded.done():
                self.agent_responded.set_exception(e)

    # region INQUIRE commands sent from gpg-agent
    #

    async def inquire_KEYPARAM(self, untrusted_args):
        if untrusted_args:
            self.server.abort('unexpected arguments to KEYPARAM inquire')
        await self.server.send_inquire(b'KEYPARAM', {
            b'D': self.inquire_command_D,
            b'END': self.inquire_command_END,
        })

    async def inquire_PINENTRY_LAUNCHED(self, untrusted_args):
        args = untrusted_args

        await self.server.send_inquire(b'PINENTRY_LAUNCHED ' + args, {
            b'END': self.inquire_command_END,
        })

    async def inquire_CIPHERTEXT(self, untrusted_args):
        if untrusted_args:
            self.server.abort('unexpected arguments to CIPHERTEXT inquire')
        await self.server.send_inquire(b'CIPHERTEXT', {
            b'D': self.inquire_command_D,
            b'END': self.inquire_command_END,
        })

    # endregion

    # region INQUIRE responses sent by client back to the agent
    #
    # each function returns whether further responses are expected

    async def inquire_command_D(self, *, untrusted_args):
        # XXX: should we sanitize this here?
        self.agent_write(b'D ' + untrusted_args + b'\n')
        return True

    async def inquire_command_END(self, *, untrusted_args):
        if untrusted_args:
            self.server.abort('unexpected arguments to END')
        self.agent_write(b'END\n')
        return False

    # endregion


TIMER_NAMES = {
    'QUBES_SPLIT_GPG2_PKSIGN_AUTOACCEPT_TIME': 'PKSIGN',
    'QUBES_SPLIT_GPG2_PKDECRYPT_AUTOACCEPT_TIME': 'PKDECRYPT',
}


def main():
    # request bi-directional socket on stdin
    if 'QREXEC_AGENT_PID' in os.environ:
        try:
            os.kill(int(os.environ['QREXEC_AGENT_PID']), signal.SIGUSR1)
        except ProcessLookupError:
            pass

    client_domain = os.environ['QREXEC_REMOTE_DOMAIN']
    loop = asyncio.get_event_loop()
    sock = socket.fromfd(sys.stdin.fileno(), socket.AF_UNIX, socket.SOCK_STREAM)
    _, protocol = loop.run_until_complete(
        loop.connect_accepted_socket(
            lambda: ServerProtocol(client_domain), sock))
    assert isinstance(protocol, ServerProtocol)

    debug_log = os.environ.get('QUBES_SPLIT_GPG2_DEBUG_LOG', None)
    if debug_log:
        handler = logging.FileHandler(debug_log)
        protocol.log.addHandler(handler)
        protocol.log.setLevel(logging.DEBUG)

    for timer in TIMER_NAMES:
        if timer in os.environ:
            protocol.timer_delay[TIMER_NAMES[timer]] = int(os.environ[timer])

    if os.environ.get('QUBES_SPLIT_GPG2_VERBOSE_NOTIFICATIONS', False) == 'yes':
        protocol.verbose_notifications = True

    connection_terminated = loop.create_future()
    protocol.notify_on_disconnect.add(connection_terminated)
    loop.run_until_complete(connection_terminated)


if __name__ == '__main__':
    main()
