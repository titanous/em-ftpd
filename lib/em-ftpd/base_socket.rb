module EM::FTPD
  module BaseSocket

    attr_reader :aborted

    def initialize(ssl_config = nil)
      @on_stream         = nil
      @aborted           = false
      @ready_for_writing = false
      @ssl_config        = ssl_config
    end

    def post_init
      super
      if @ssl_config
        start_tls(@ssl_config)
      else
        @ready_for_writing = true
      end
    end

    def ssl_handshake_completed
      @ready_for_writing = true
    end

    def ready_for_writing?
      @ready_for_writing
    end

    def on_stream &blk
      @on_stream = blk if block_given?
      unless data.empty?
        @on_stream.call(data) # send all data that was collected before the stream hanlder was set
        @data = ""
      end
      @on_stream
    end

    def data
      @data ||= ""
    end

    def receive_data(chunk)
      if @on_stream
        @on_stream.call(chunk)
      else
        data << chunk
      end
    end

    def unbind
      if @aborted
        fail
      else
        if @on_stream
          succeed
        else
          succeed data
        end
      end
    end

    def abort
      @aborted = true
      close_connection_after_writing
    end
  end
end
