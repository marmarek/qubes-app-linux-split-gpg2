#!/usr/bin/env ruby

require 'socket'

if ARGV.length != 1
  $stderr.puts "Usage: #{$0} /path/to/fake-gpg-agent-socket"
  exit 1
end

fake_s_path = ARGV[0]

system 'gpgconf', '--launch', 'gpg-agent'

gc_out_r, gc_out_w = IO.pipe
Process.wait(spawn('gpgconf', '--list-dirs', out: gc_out_w))
gc_out_w.close
real_s_path = gc_out_r.read.split("\n").map{|i| i.split(':', 2)}.find{|i| i[0] == 'agent-socket'}[1]

puts "real gpg-agent socket: #{real_s_path}"

@log_f = File.open "#{fake_s_path}.log", 'a'
@log_f.sync = true
@log_m = Monitor.new

def log(m)
  s = m.split("\n").map{|i| "#{Time.now.strftime '%Y-%m-%d %H:%M:%S.%N'}: #{i}"}.join("\n")
  @log_m.synchronize{@log_f.puts s}
end

# XXX: not thread safe
begin
  UNIXSocket.new fake_s_path
  $stderr.puts 'fake socket already in use'
  exit 1
rescue Errno::ECONNREFUSED
  File.unlink fake_s_path
rescue Errno::ENOENT
end
fake_s = UNIXServer.new fake_s_path

i = 0
begin
  while c = fake_s.accept
    log "#{i}: connected"
    s = UNIXSocket.new real_s_path

    Thread.new(c, s, i) do |c, s, i|
      while l = c.gets
        l.chop!
        log "#{i}: >>> #{l}"
        s.puts l
      end
      unless s.closed?
        s.close
        log "#{i}: disconnected"
      end
    end

    Thread.new(c, s, i) do |c, s, i|
      while l = s.gets
        l.chop!
        log "#{i}: <<< #{l}"
        c.puts l
      end
      unless c.closed?
        c.close
        log "#{i}: disconnected"
      end
    end

    i += 1
  end
rescue Interrupt
  puts
end
