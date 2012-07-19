module EM::FTPD
  # An eventmachine module for connecting to a remote
  # port and downloading a file
  #
  class ActiveSocket < EventMachine::Connection
    include EM::Deferrable
    include BaseSocket

    def self.open(host, port, ssl_config)
      EventMachine.connect(host, port, self, ssl_config)
    end

  end
end
