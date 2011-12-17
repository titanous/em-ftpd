# coding: utf-8

module EM::FTPD

  class Configurator

    def initialize
      @user             = nil
      @group            = nil
      @daemonise        = false
      @name             = nil
      @pid_file         = nil
      @port             = 21

      @driver           = nil
      @driver_args      = []

      @enforce_tls        = false
      @enforce_data_tls   = false
      @private_key_file = nil
      @cert_chain_file  = nil
    end

    def user(val = nil)
      if val
        @user = val.to_s
      else
        @user
      end
    end

    def uid
      return nil if @user.nil?

      begin
        detail = Etc.getpwnam(@user)
        return detail.uid
      rescue
        $stderr.puts "user must be nil or a real account" if detail.nil?
      end
    end

    def group(val = nil)
      if val
        @group = val.to_s
      else
        @group
      end
    end

    def gid
      return nil if @group.nil?

      begin
        detail = Etc.getpwnam(@group)
        return detail.gid
      rescue
        $stderr.puts "group must be nil or a real group" if detail.nil?
      end
    end


    def daemonise(val = nil)
      if !val.nil?
        @daemonise = !!val
      else
        @daemonise
      end
    end

    def driver(klass = nil)
      if klass
        @driver = klass
      else
        @driver
      end
    end

    def driver_args(*args)
      if args.empty?
        @driver_args
      else
        @driver_args = args
      end
    end

    def name(val = nil)
      if val
        @name = val.to_s
      else
        @name
      end
    end

    def pid_file(val = nil)
      if val
        @pid_file = val.to_s
      else
        @pid_file
      end
    end

    def port(val = nil)
      if val
        @port = val.to_i
      else
        @port
      end
    end

    def enforce_tls(val = nil)
      if !val.nil?
        @enforce_tls = !!val
      else
        @enforce_tls
      end
    end

    def enforce_data_tls(val = nil)
      if !val.nil?
        @enforce_data_tls = !!val
      else
        @enforce_data_tls
      end
    end

    def private_key_file(val = nil)
      if val
        @private_key_file = val
      else
        @private_key_file
      end
    end

    def cert_chain_file(val = nil)
      if val
        @cert_chain_file = val
      else
        @cert_chain_file
      end
    end

    def check!
      if @driver.nil?
        die("driver MUST be specified in the config file")
      end
      if (@enforce_tls || @enforce_data_tls) && (@private_key_file.nil? || @cert_chain_file.nil?)
        die("private_key_file and cert_chain_file MUST be specified when enabling enforce_tls or enforce_data_tls")
      end
      if @private_key_file && !File.readable?(@private_key_file)
        die("private_key_file #{@private_key_file} not readable")
      end
      if @cert_chain_file && !File.readable?(@cert_chain_file)
        die("cert_chain_file #{@cert_chain_file} not readable")
      end
      if (@private_key_file && !@cert_chain_file) || (!@private_key_file && @cert_chain_file)
        die("private_key_file and cert_chain_file must be both speficied")
      end
      if (@private_key_file && !EM.ssl?)
        die("Your EventMachine does not support SSL/TLS. Please install open_ssl and try again.")
      end
    end

    private

    def die(msg)
      $stderr.puts msg
      exit 1
    end
  end

end
