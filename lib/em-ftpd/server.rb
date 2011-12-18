require 'socket'
require 'stringio'

require 'eventmachine'
require 'em/protocols/line_protocol'

module EM::FTPD
  class Server < EM::Connection

    LBRK = "\r\n"

    include EM::Protocols::LineProtocol
    include StandardResponses
    include Authentication
    include Directories
    include Files
    include DataSockets
    include Security

    COMMANDS = %w[quit type user retr stor eprt port cdup cwd dele rmd pwd
                  list size syst mkd pass xcup xpwd xcwd xrmd rest allo nlst
                  pasv epsv help noop mode rnfr rnto stru feat]

    COMMANDS.concat %w(auth pbsz prot) if EM.ssl?

    attr_reader :root, :name_prefix
    attr_accessor :datasocket

    def initialize(driver, driver_args = [], config = Configurator.new)
      if driver.is_a?(Class)
        @driver   = driver.new *driver_args
      else
        @driver   = driver
      end
      @config     = config
      super()
    end

    def post_init
      @mode        = :binary
      @name_prefix = "/"

      if @config.name
        send_response "220 FTP server (em-ftpd/#{@config.name}) ready"
      else
        send_response "220 FTP server (em-ftpd) ready"
      end
    end

    def receive_line(str)
      cmd, param = parse_request(str)

      # if the command is contained in the whitelist, and there is a method
      # to handle it, call it. Otherwise send an appropriate response to the
      # client
      if COMMANDS.include?(cmd) && self.respond_to?("cmd_#{cmd}".to_sym, true)
        begin
          self.__send__("cmd_#{cmd}".to_sym, param)
        rescue Exception => err
          puts "#{err.class}: #{err}"
          puts err.backtrace.join("\n")
          close_datasocket
          close_connection_after_writing
        end
      else
        send_response "500 Sorry, I don't understand #{cmd.upcase}"
      end
    end

    private

    def build_path(filename = nil)
      if filename && filename[0,1] == "/"
        path = File.expand_path(filename)
      elsif filename && filename != '-a'
        path = File.expand_path("#{@name_prefix}/#{filename}")
      else
        path = File.expand_path(@name_prefix)
      end
      path.gsub(/\/+/,"/")
    end

    # split a client's request into command and parameter components
    def parse_request(data)
      data.strip!
      space = data.index(" ")
      if space
        cmd = data[0, space]
        param = data[space+1, data.length - space]
        param = nil if param.strip.size == 0
      else
        cmd = data
        param = nil
      end

      [cmd.downcase, param]
    end

    def cmd_allo(param)
      send_response "202 Obsolete"
    end

    # handle the HELP FTP command by sending a list of available commands.
    def cmd_help(param)
      send_response "214- The following commands are recognized."
      commands = COMMANDS
      str = ""
      commands.sort.each_slice(3) { |slice|
        str += "     " + slice.join("\t\t") + LBRK
      }
      send_response str, true
      send_response "214 End of list."
    end

    def cmd_feat(param)
      str = "211- Supported features:#{LBRK}"
      features = ["EPRT", "EPSV", "SIZE", "AUTH TLS", "PBSZ", "PROT" ]
      features.each do |feat|
        str << " #{feat}" << LBRK
      end
      str << "211 END" << LBRK

      send_response(str, true)
    end

    # the original FTP spec had various options for hosts to negotiate how data
    # would be sent over the data socket, In reality these days (S)tream mode
    # is all that is used for the mode - data is just streamed down the data
    # socket unchanged.
    #
    def cmd_mode(param)
      send_unauthorised and return unless logged_in?
      send_param_required and return if param.nil?
      if param.upcase.eql?("S")
        send_response "200 OK"
      else
        send_response "504 MODE is an obsolete command"
      end
    end

    # handle the NOOP FTP command. This is essentially a ping from the client
    # so we just respond with an empty 200 message.
    def cmd_noop(param)
      send_response "200"
    end

    

    # handle the QUIT FTP command by closing the connection
    def cmd_quit(param)
      send_response "221 Bye"
      close_datasocket
      close_connection_after_writing
    end


    # like the MODE and TYPE commands, stru[cture] dates back to a time when the FTP
    # protocol was more aware of the content of the files it was transferring, and
    # would sometimes be expected to translate things like EOL markers on the fly.
    #
    # These days files are sent unmodified, and F(ile) mode is the only one we
    # really need to support.
    def cmd_stru(param)
      send_param_required and return if param.nil?
      send_unauthorised and return unless logged_in?
      if param.upcase.eql?("F")
        send_response "200 OK"
      else
        send_response "504 STRU is an obsolete command"
      end
    end

    # return the name of the server
    def cmd_syst(param)
      send_unauthorised and return unless logged_in?
      send_response "215 UNIX Type: L8"
    end

    # like the MODE and STRU commands, TYPE dates back to a time when the FTP
    # protocol was more aware of the content of the files it was transferring, and
    # would sometimes be expected to translate things like EOL markers on the fly.
    #
    # Valid options were A(SCII), I(mage), E(BCDIC) or LN (for local type). Since
    # we plan to just accept bytes from the client unchanged, I think Image mode is
    # adequate. The RFC requires we accept ASCII mode however, so accept it, but
    # ignore it.
    def cmd_type(param)
      send_unauthorised and return unless logged_in?
      send_param_required and return if param.nil?
      if param.upcase.eql?("A")
        send_response "200 Type set to ASCII"
      elsif param.upcase.eql?("I")
        send_response "200 Type set to binary"
      else
        send_response "500 Invalid type"
      end
    end

    # all responses from an FTP server end with \r\n, so wrap the
    # send_data callback
    def send_response(msg, no_linebreak = false)
      msg += LBRK unless no_linebreak
      send_data msg
    end

  end
end
