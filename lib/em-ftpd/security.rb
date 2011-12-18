module EM::FTPD
  # 
  # Encrypted control and data channel support.
  # Implements most parts of RFC 4217 (http://tools.ietf.org/html/rfc4217)
  # 
  # This module must be included into EM::FTPD::Server AFTER the other modules have been included
  module Security

    def initialize(*args)
      super if defined?(super)
      @command_channel_secure = false
      @client_wants_secure_data_channel = false
      @has_pbsz = false
    end

    def ssl_config
      {
        :private_key_file => @config.private_key_file,
        :cert_chain_file  => @config.cert_chain_file
      }
    end

    def ssl_config_for_data_channel
      ssl_config if client_wants_secure_data_channel?
    end

    def valid_ssl_config?
      !!(EM.ssl? && 
              @config.private_key_file && File.readable?(@config.private_key_file) && 
              @config.cert_chain_file && File.readable?(@config.cert_chain_file))
    end

    #
    # command channel

    def enforce_secure_command_channel?
      @config.enforce_tls
    end

    def command_channel_secure?
      @command_channel_secure
    end

    def ssl_handshake_completed
      @command_channel_secure = true
      super
    end

    def cmd_auth(param)
      send_param_required and return if param.nil?
      send_response("534 Server only speaks AUTH TLS") and return if param.upcase != "TLS"
      send_response("431 Sorry, server is not configured for AUTH TLS") and return unless valid_ssl_config?
      send_response("234 OK, starting TLS on command channel")
      @has_pbsz = false
      start_tls(ssl_config)
    end


    #
    # data channel

    def enforce_secure_data_channel?
      @config.enforce_data_tls
    end

    def client_wants_secure_data_channel?
      @client_wants_secure_data_channel
    end

    def reject_insecure_data_channel?
      enforce_secure_data_channel? && !client_wants_secure_data_channel?
    end

    def cmd_pbsz(param)
      send_param_required and return if param.nil?
      send_response("503 PBSZ needs AUTH TLS first") and return unless command_channel_secure?
      @has_pbsz = true
      send_response "200 PBSZ=0"
    end

    def cmd_prot(param)
      send_param_required and return if param.nil?
      send_response("503 PROT needs AUTH TLS and PBSZ first") and return unless command_channel_secure? && @has_pbsz
      if %w(C P).include? param.upcase
        @client_wants_secure_data_channel = param.upcase == "P"
        send_response "200 #{@client_wants_secure_data_channel ? 'private' : 'clear text'} data channel protection selected"
      else
        send_response "534 only _C_LEAR and _P_RIVATE are allowed for TLS"
      end
    end


    #
    # override commands of other modules to enforce our security constrains
    #

    #
    # This override optionally ensures that AUTH TLS was called before a USER call
    def cmd_user(param)
      if enforce_secure_command_channel? && !command_channel_secure?
        send_response("521 This server enforces the use of AUTH TLS before log in")
      else
        super
      end
    end

    #
    # These overrides optionally ensure that the data channel is secure.
    def cmd_stor(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_retr(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_nlst(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_list(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_stou(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_appe(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    
    #
    # These overrides block active connections with TLS security.
    # For now that does not seem to work. Probably because of EventMachine's rudimentary OpenSSL integration.
    def cmd_port(param); send_passive_ftp_needed and return if client_wants_secure_data_channel?; super; end
    def cmd_eprt(param); send_passive_ftp_needed and return if client_wants_secure_data_channel?; super; end


    def send_secure_data_channel_needed
      send_response("521 data connection cannot be opened with this PROT setting")
    end

    def send_passive_ftp_needed
      send_response("521 sorry, my bad, but you have to use passive ftp with AUTH TLS for now")
    end

  end
end
