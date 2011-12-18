module EM::FTPD
  module StandardResponses
    def send_param_required
      send_response "553 action aborted, required param missing"
    end

    def send_permission_denied
      send_response "550 Permission denied"
    end

    def send_action_not_taken
      send_response "550 Action not taken"
    end

    def send_illegal_params
      send_response "553 action aborted, illegal params"
    end

    def send_unauthorised
      send_response "530 Not logged in"
    end
  end
end
