module EM::FTPD
  module DataSockets
    
    LBRK = "\r\n"

    def initialize
      super
      @datasocket = nil
      @listen_sig = nil
    end

    # Passive FTP. At the clients request, listen on a port for an incoming
    # data connection. The listening socket is opened on a random port, so
    # the host and port is sent back to the client on the control socket.
    #
    def cmd_pasv(param)
      send_unauthorised and return unless logged_in?

      host, port = start_passive_socket

      p1, p2 = *port.divmod(256)

      send_response "227 Entering Passive Mode (" + host.split(".").join(",") + ",#{p1},#{p2})"
    end

    # listen on a port, see RFC 2428
    #
    def cmd_epsv(param)
      host, port = start_passive_socket

      send_response "229 Entering Extended Passive Mode (|||#{port}|)"
    end

    # Active FTP. An alternative to Passive FTP. The client has a listening socket
    # open, waiting for us to connect and establish a data socket. Attempt to
    # open a connection to the host and port they specify and save the connection,
    # ready for either end to send something down it.
    def cmd_port(param)
      send_unauthorised and return unless logged_in?
      send_param_required and return if param.nil?

      nums = param.split(',')
      port = nums[4].to_i * 256 + nums[5].to_i
      host = nums[0..3].join('.')
      close_datasocket

      puts "connecting to client #{host} on #{port}"
      @datasocket = ActiveSocket.open(host, port, ssl_config_for_data_channel)

      puts "Opened active connection at #{host}:#{port}"
      send_response "200 Connection established (#{port})"
    rescue Exception => err
      # puts "#{err.class}: #{err}"
      # puts err.backtrace.join("\n")
      puts "Error opening data connection to #{host}:#{port}"
      send_response "425 Data connection failed"
    end

    # Active FTP.
    #
    def cmd_eprt(param)
      send_unauthorised and return unless logged_in?
      send_param_required and return if param.nil?

      delim = param[0,1]
      m, af, host, port = *param.match(/#{delim}(.+?)#{delim}(.+?)#{delim}(.+?)#{delim}/)
      port = port.to_i
      close_datasocket

      if af.to_i != 1 && ad.to_i != 2
        send_response "522 Network protocol not supported, use (1,2)"
      else
        puts "connecting to client #{host} on #{port}"
        @datasocket = ActiveSocket.open(host, port, ssl_config_for_data_channel)

        puts "Opened active connection at #{host}:#{port}"
        send_response "200 Connection established (#{port})"
      end
    rescue
      puts "Error opening data connection to #{host}:#{port}"
      send_response "425 Data connection failed"
    end


    def close_datasocket
      if @datasocket
        @datasocket.close_connection_after_writing
        @datasocket = nil
      end

      # stop listening for data socket connections, we have one
      if @listen_sig
        PassiveSocket.stop(@listen_sig)
        @listen_sig = nil
      end
    end

    # waits for the data socket to be established
    def wait_for_datasocket(interval = 0.1, &block)
      if @datasocket.nil? && interval < 25
        if EM.reactor_running?
          EventMachine.add_timer(interval) { wait_for_datasocket(interval * 2, &block) }
        else
          sleep interval
          wait_for_datasocket(interval * 2, &block)
        end
        return
      end
      yield @datasocket
    end

    # receive a file data from the client across the data socket.
    #
    # The data socket is NOT guaranteed to be setup by the time this method runs.
    # If this happens, exit the method early and try again later. See the method
    # comments to send_outofband_data for further explanation.
    #
    def receive_outofband_data(&block)
      wait_for_datasocket do |datasocket|
        if datasocket.nil?
          send_response "425 Error establishing connection"
          yield false
          return
        end

        # let the client know we're ready to start
        send_response "150 Data transfer starting"

        datasocket.callback do |data|
          block.call(data)
        end
      end
    end

    def start_passive_socket
      # close any existing data socket
      close_datasocket

      # grab the host/address the current connection is
      # operating on
      host = Socket.unpack_sockaddr_in( self.get_sockname ).last

      # open a listening socket on the appropriate host
      # and on a random port
      @listen_sig = PassiveSocket.start(host, self, ssl_config_for_data_channel)
      port = PassiveSocket.get_port(@listen_sig)

      [host, port]
    end

    # send data to the client across the data socket.
    #
    # The data socket is NOT guaranteed to be setup by the time this method runs.
    # If it isn't ready yet, exit the method and try again on the next reactor
    # tick. This is particularly likely with some clients that operate in passive
    # mode. They get a message on the control port with the data port details, so
    # they start up a new data connection AND send they command that will use it
    # in close succession.
    #
    # The data port setup needs to complete a TCP handshake before it will be
    # ready to use, so it may take a few RTTs after the command is received at
    # the server before the data socket is ready.
    #
    def send_outofband_data(data, interval = 0.1)
      wait_for_datasocket do |datasocket|
        if datasocket.nil?
          send_response "425 Error establishing connection"
        elsif !@datasocket.ready_for_writing?
          if interval > 25
            send_response "425 Error while establishing connection. SSL handshake failure?"
            close_datasocket
          else
            if EM.reactor_running?
              EventMachine.add_timer(interval) { send_outofband_data(data, interval * 2) }
            else
              sleep interval
              send_outofband_data(data, interval * 2)
            end
          end
        else
          if data.is_a?(Array)
            data = data.join(LBRK) << LBRK
          end
          data = StringIO.new(data) if data.kind_of?(String)


          if EM.reactor_running?
            # send the data out in chunks, as fast as the client can recieve it -- not blocking the reactor in the process
            streamer = IOStreamer.new(datasocket, data)
            finalize = Proc.new {
              close_datasocket
              data.close if data.respond_to?(:close) && !data.closed?
            }
            streamer.callback {
              send_response "226 Closing data connection, sent #{streamer.bytes_streamed} bytes"
              finalize.call
            }
            streamer.errback { |ex| 
              send_response "425 Error while streaming data, sent #{streamer.bytes_streamed} bytes"
              finalize.call
              raise ex 
            }
          else
            # blocks until all data is sent
            begin
              bytes = 0
              data.each do |line|
                datasocket.send_data(line)
                bytes += line.bytesize
              end
              send_response "226 Closing data connection, sent #{bytes} bytes"
            ensure
              close_datasocket
              data.close if data.respond_to?(:close) && !data.closed?
            end
          end
        end
        
      end
    end

  end
end
