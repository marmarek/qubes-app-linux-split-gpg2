# split-gpg2.rb
# Copyright (C) 2014  HW42 <hw42@ipsumj.de>
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

require 'socket'
require 'fileutils'

module SplitGPG2
  class Error < ::StandardError
    class GPGAgent < self
      class StartFailed < self
      end

      class GetSocketPathFailed < self
      end

      class ProtocolError < self
      end

      class Filtered < self
        def code
          GPGCode::SOURCE_GPGAGENT << GPGCode::SOURCE_SHIFT |
            GPGCode::ERR_USER_1
        end

        def gpg_message
          "Command filtered by split-gpg2."
        end
      end
    end

    module GPGCode
      # see gpg-error.h
      SOURCE_SHIFT = 24
      SOURCE_GPGAGENT = 4
      ERR_USER_1 = 1024
      ERR_ASS_UNKNOWN_CMD = 275

      UnknownIPCCommand = SOURCE_GPGAGENT << SOURCE_SHIFT | ERR_ASS_UNKNOWN_CMD
    end
  end

  # from assuan.h
  ASSUAN_LINELENGTH = 1002

  class Server
    attr_reader :commands, :options, :hash_algos, :timer_delay
    attr_accessor :log, :verbose_notifications

    # +cin+:: client input IO-object
    # +cout+:: client output IO-object
    # +client_domain+:: name of the connected client vm
    def initialize(cin, cout, client_domain)
      @cin = cin
      @cout = cout
      @client_domain = client_domain

      @cin.sync = true
      @cout.sync = true

      # prevent unicode parsing bugs
      @cin.set_encoding 'ASCII-8BIT:ASCII-8BIT'
      @cout.set_encoding 'ASCII-8BIT:ASCII-8BIT'

      @commands = default_commands
      @options = default_options
      @hash_algos = default_hash_algos
      @timer_delay = default_timer_delay
      @verbose_notifications = false

      @log_m = Monitor.new

      connect_agent
    end

    private

    # Ensure that a local gpg-agent runns and connect to it.
    def connect_agent
      unless system 'gpgconf', '--launch', 'gpg-agent'
        raise Error::GPGAgent::StartFailed
      end

      gc_out_r, gc_out_w = IO.pipe
      Process.wait(spawn('gpgconf', '--list-dirs', out: gc_out_w))
      gc_out_w.close
      gc_lines = gc_out_r.read.split("\n")
      sp = gc_lines.map{|i| i.split(':', 2)}.find{|i| i[0] == 'agent-socket'}

      unless sp && sp[1] && File.socket?(sp[1])
        raise Error::GPGAgent::GetSocketPathFailed
      end
      @agent_socket_path = sp[1]

      @agent = UNIXSocket.new @agent_socket_path
      @agent.set_encoding 'ASCII-8BIT:ASCII-8BIT'
      nil
    end

    public

    # Main loop.
    def run
      begin
        log_io 'connected', ''
        if @verbose_notifications
          notify 'connected'
        end
        handle_server_response nil, {}
        while untrusted_l = cin_gets
          untrusted_cmd, untrusted_args = untrusted_l.chop.split " ", 2
          command = @commands[untrusted_cmd]

          unless command
            raise Error::GPGAgent::Filtered
          end

          command.call untrusted_args
        end
      rescue Error::GPGAgent::Filtered => e
        notify "command filtered out"

        cout_write "ERR #{e.code} #{e.gpg_message}\n"
        # break handling since we aren't sure that clients handle the error
        # correctly. This makes the filtering easier to implement and we ensure
        # that a client does not wrongly assume that a command was successful
        # while is was indeed filtered out.
      ensure
        log_io 'disconnected', ''
        if @verbose_notifications
          notify 'disconnected'
        end
      end
    end

    def default_commands
      {
        'RESET' => method(:command_RESET),
        'OPTION' => method(:command_OPTION),
        'AGENT_ID' => method(:command_AGENT_ID),
        'HAVEKEY' => method(:command_HAVEKEY),
        'KEYINFO' => method(:command_KEYINFO),
        'GENKEY' => method(:command_GENKEY),
        'SIGKEY' => method(:command_SIGKEY),
        'SETKEY' => method(:command_SETKEY),
        'SETKEYDESC' => method(:command_SETKEYDESC),
        'PKDECRYPT' => method(:command_PKDECRYPT),
        'SETHASH' => method(:command_SETHASH),
        'PKSIGN' => method(:command_PKSIGN),
        'GETINFO' => method(:command_GETINFO),
        'BYE' => method(:command_BYE)
      }
    end

    def default_options
      {
        # should be overriden on startup to reflect sensible values
        'ttyname' => [:fake, 'OK'],
        'ttytype' => [:fake, 'OK'],
        'display' => [:override, ':0'],
        'lc-ctype' => [:fake, 'OK'],
        'lc-messages' => [:fake, 'OK'],
        'putenv' => [:fake, 'OK'],
        'allow-pinentry-notify' => [:verify, nil],
        'agent-awareness' => [:verify, '2.1.0']
      }
    end

    def default_timer_delay
      {
        PKSIGN: nil,     # always query for signing
        PKDECRYPT: 300 # 5 min
      }
    end

    def default_hash_algos
      {
        2 => {name: 'sha1', len: 40},
        3 => {name: 'rmd160', len: 40},
        8 => {name: 'sha256', len: 64},
        9 => {name: 'sha384', len: 96},
        10 => {name: 'sha512', len: 128},
        11 => {name: 'sha224', len: 56}
      }
    end

    private

    # IO helper from/to agent/client. These automaticaly log the IO if logging
    # is enabled.

    def cin_gets
      if @cin.closed?
        return nil
      end

      @log_m.synchronize do
        untrusted_l = @cin.gets("\n", ASSUAN_LINELENGTH + 1)
        if untrusted_l && untrusted_l.length > ASSUAN_LINELENGTH
          raise Error::GPGAgent::Filtered
        end
        log_io 'C >>>', untrusted_l
        untrusted_l
      end
    end

    def cout_write(msg)
      @log_m.synchronize do
        log_io 'C <<<', msg
        @cout.write msg
      end
    end

    def agent_gets
      @log_m.synchronize do
        untrusted_l = @agent.gets("\n")
        log_io 'A >>>', untrusted_l
        untrusted_l
      end
    end

    def agent_write(msg)
      @log_m.synchronize do
        log_io 'A <<<', msg
        @agent.write msg
      end
    end

    # Log messasge.
    # +prefix+:: prefix to put infront of the logged message.
    # +untrusted_msg+:: message to log. Will be santizied before written to log
    def log_io(prefix, untrusted_msg)
      unless @log && untrusted_msg
        return
      end

      now = Time.now
      print_ascii = (0x20..0x7e).map{|i| i.chr}
      msg = untrusted_msg.chop.chars.
        map{|c| print_ascii.include?(c) ? c : '.'}.join
      @log_m.synchronize do
        @log.write("#{now.strftime('%Y-%m-%d %H:%M:%S.%N')}: " <<
          "#{Process.pid}: #{prefix} #{msg}\n")
      end
    end

    def assert_no_arguments(untrusted_args)
      if untrusted_args
        raise Error::GPGAgent::Filtered
      end
      nil
    end

    def assert_keygrip_arguments(min, max, untrusted_args)
      args_regex = /\A[0-9A-F]{40}( [0-9A-F]{40}){#{min - 1},#{max - 1}}\z/
      unless args_regex.match(untrusted_args)
        raise Error::GPGAgent::Filtered
      end
      untrusted_args
    end

    def sanitize_key_desc(untrusted_args)
      untrusted_args = untrusted_args.dup
      untrusted_args.gsub!('+', ' ')
      untrusted_args.gsub!(/%([0-9A-F]{2})/){|i| i[1,2].to_i(16).chr}
      allowed_ascii = ((0x20..0x7e).to_a + [0x0a]).map{|i| i.chr}
      args = "Message from '#{@client_domain}':\n"
      args << untrusted_args.chars.map do |c|
        allowed_ascii.include?(c) ? c : '.'
      end.join
      args.gsub!('%', '%25')
      args.gsub!('+', '%2B')
      args.gsub!("\n", '%0A')
      args.gsub!(' ', '+')
      args
    end

    def fake_respond(res)
      cout_write res + "\n"
    end

    def handle_server_response(cmd, inquiries)
      if cmd
        agent_write cmd + "\n"
      end

      # We gennerally consider the agent as trusted. But since the client can
      # determine part of the response we handle this here as untrusted.
      while untrusted_l = agent_gets
        untrusted_res, untrusted_args = untrusted_l.chop.split(' ', 2)
        if ['D', 'S'].include? untrusted_res
          cout_write untrusted_l
        elsif ['OK', 'ERR'].include? untrusted_res
          cout_write untrusted_l
          break
        elsif untrusted_res == 'INQUIRE'
          unless untrusted_args
            raise Error::GPGAgent::Filtered
          end

          untrusted_inq, untrusted_inq_args = untrusted_args.split(' ', 2)
          inquire = inquiries[untrusted_inq]
          unless inquire
            raise Error::GPGAgent::Filtered
          end

          inquire.call untrusted_inq_args
        else
          raise ProtocolError.new 'unexpected server response'
        end
      end
    end

    def handle_inquire(inq, inquire_commands)
      cout_write "INQUIRE #{inq}\n"
      while untrusted_l = cin_gets
        untrusted_icmd, untrusted_args = untrusted_l.chop.split(' ', 2)
        inquire_command = inquire_commands[untrusted_icmd]
        unless inquire_command
          raise Error::GPGAgent::Filtered
        end

        cont = inquire_command.call untrusted_args
        unless cont
          break
        end
      end
    end

    def send_inquire_command(cmd)
      agent_write cmd + "\n"
    end

    def request_timer(name)
      now = Time.now
 
      delay = @timer_delay[name]
      ts = timestamp_path name
      if delay
        mtime = File.mtime(ts) rescue nil
        if mtime && (mtime + delay) > now
          notify "command '#{name}' automatically allowed"
          return
        end
      end

      short_msg =  "split-gpg2: '#{@client_domain}' wants to execute #{name}"
      question = short_msg.dup
      question << "\nDo you want to allow this"
      question << (delay ? " for the next #{delay} s?" : '?')

      unless system('zenity', '--question', '--title', short_msg, '--text',
                    question)
        raise Error::GPGAgent::Filtered
      end

      notify "command '#{name}' allowed"

      FileUtils.touch ts
    end

    def notify(msg)
      system 'notify-send', "split-gpg2: '#{@client_domain}': #{msg}"
    end

    def timestamp_path(name)
      "#{@agent_socket_path}_qubes-split-gpg2-timestamp_#{name}"
    end

    def command_RESET(untrusted_args)
      assert_no_arguments untrusted_args
      handle_server_response 'RESET', {}
    end

    def command_OPTION(untrusted_args)
      unless untrusted_args
        raise Error::GPGAgent::Filtered
      end

      untrusted_name, untrusted_value = untrusted_args.split('=', 2)
      action, opts = @options[untrusted_name]

      if action
        name = untrusted_name
      end

      case action
      when :override
        if opts
          cmd = "OPTION #{name}=#{opts}"
        else
          cmd = "OPTION #{name}"
        end

      when :verify
        verified = false
        if opts.respond_to?(:call)
          verified = opts.call untrusted_value
        elsif opts.kind_of? Regexp
          verified = opts.match(untrusted_value)
        else
          verified = opts == untrusted_value
        end

        unless verified
          raise Error::GPGAgent::Filtered
        end
        value = untrusted_value

        if value
          cmd = "OPTION #{name}=#{value}"
        else
          cmd = "OPTION #{name}"
        end

      when :fake
        return fake_respond opts

      else
        raise Error::GPGAgent::Filtered
      end

      handle_server_response cmd, {}
    end

    def command_AGENT_ID(untrusted_args)
      fake_respond(
        "ERR #{Error::GPGCode::UnknownIPCCommand} unknown IPC command")
    end

    def command_HAVEKEY(untrusted_args)
      # upper keygrip limit is arbitary
      args = assert_keygrip_arguments 1, 200, untrusted_args
      handle_server_response "HAVEKEY #{args}", {}
    end

    def command_KEYINFO(untrusted_args)
      args = assert_keygrip_arguments 1, 1, untrusted_args
      handle_server_response "KEYINFO #{args}", {}
    end

    def command_GENKEY(untrusted_args)
      if untrusted_args && !/\A[0-9A-F]{24}\z/.match(untrusted_args)
        raise Error::GPGAgent::Filtered
      end
      args = untrusted_args

      cmd = 'GENKEY'
      cmd += " #{args}" if args

      handle_server_response cmd, {
        'KEYPARAM' => method(:inquire_KEYPARAM),
        'PINENTRY_LAUNCHED' => method(:inquire_PINENTRY_LAUNCHED)
      }
    end

    def command_SIGKEY(untrusted_args)
      args = assert_keygrip_arguments 1, 1, untrusted_args
      handle_server_response "SIGKEY #{args}", {}
    end

    def command_SETKEY(untrusted_args)
      args = assert_keygrip_arguments 1, 1, untrusted_args
      handle_server_response "SETKEY #{args}", {}
    end

    def command_SETKEYDESC(untrusted_args)
      # XXX: is there a better way than showing the message
      #      from the untrusted domain
      args = sanitize_key_desc(untrusted_args)

      handle_server_response "SETKEYDESC #{args}", {}
    end

    def command_PKDECRYPT(untrusted_args)
      request_timer :PKDECRYPT

      assert_no_arguments untrusted_args
      handle_server_response 'PKDECRYPT', {
        'CIPHERTEXT' => method(:inquire_CIPHERTEXT),
        'PINENTRY_LAUNCHED' => method(:inquire_PINENTRY_LAUNCHED)
      }
    end

    def command_SETHASH(untrusted_args)
      untrusted_alg, untrusted_hash = untrusted_args.split(' ', 2)
      alg = untrusted_alg.to_i
      alg_param = @hash_algos[alg]
      unless alg_param
        raise Error::GPGAgent::Filtered
      end

      unless untrusted_hash
        raise Error::GPGAgent::Filtered
      end

      unless /\A[0-9A-F]{#{alg_param[:len]}}\z/.match(untrusted_hash)
        raise Error::GPGAgent::Filtered
      end
      hash = untrusted_hash
        
      handle_server_response "SETHASH #{alg} #{hash}", {}
    end

    def command_PKSIGN(untrusted_args)
      request_timer :PKSIGN

      if untrusted_args && !/\A-- [0-9A-F]{24}\z/.match(untrusted_args)
        raise Error::GPGAgent::Filtered
      end
      args = untrusted_args

      cmd = 'PKSIGN'
      cmd += " #{args}" if args

      handle_server_response cmd, {
        'PINENTRY_LAUNCHED' => method(:inquire_PINENTRY_LAUNCHED)
      }
    end

    def command_GETINFO(untrusted_args)
      if untrusted_args != 'version'
        raise Error::GPGAgent::Filtered
      end
      args = untrusted_args

      handle_server_response "GETINFO #{args}", {}
    end

    def command_BYE(untrusted_args)
      assert_no_arguments untrusted_args

      handle_server_response 'BYE', {}

      [@cin, @cout, @agent].each{|c| c.close unless c.closed?}
    end

    def inquire_KEYPARAM(untrusted_args)
      assert_no_arguments untrusted_args
      handle_inquire 'KEYPARAM', {
        'D' => method(:inquire_command_D),
        'END' => method(:inquire_command_END)
      }
    end

    def inquire_PINENTRY_LAUNCHED(untrusted_args)
      unless untrusted_args && /\A\d+\z/.match(untrusted_args)
        raise Error::GPGAgent::Filtered
      end
      args = untrusted_args

      handle_inquire "PINENTRY_LAUNCHED #{args}", {
        'END' => method(:inquire_command_END)
      }
    end

    def inquire_CIPHERTEXT(untrusted_args)
      assert_no_arguments untrusted_args
      handle_inquire 'CIPHERTEXT', {
        'D' => method(:inquire_command_D),
        'END' => method(:inquire_command_END)
      }
    end

    def inquire_command_D(untrusted_args)
      # XXX: should we sanitize this here?
      send_inquire_command "D #{untrusted_args}"
      true
    end

    def inquire_command_END(untrusted_args)
      assert_no_arguments untrusted_args
      send_inquire_command 'END'
      false
    end
  end
end
