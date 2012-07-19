# coding: utf-8

require File.dirname(__FILE__) + "/spec_helper"

module StubbedCmds
  def cmd_user(param); send_response("200 OK"); end
  def cmd_stor(param); send_response("200 OK"); end
  def cmd_retr(param); send_response("200 OK"); end
  def cmd_nlst(param); send_response("200 OK"); end
  def cmd_list(param); send_response("200 OK"); end
  def cmd_stou(param); send_response("200 OK"); end
  def cmd_appe(param); send_response("200 OK"); end
  def cmd_port(param); send_response("200 OK"); end
  def cmd_eprt(param); send_response("200 OK"); end
end

class SecurityTest
  include StubbedCmds
  include EM::FTPD::Security
  include EM::FTPD::StandardResponses

  def initialize(config = nil)
    super()
    @config    = config
    @sent_data = ""
  end

  def send_response(msg)
    @sent_data = msg # we only care about the last response sent
  end
  def sent_data
    @sent_data
  end

  def start_tls(config = {})
    @command_channel_secure = true
  end
  
end

describe EM::FTPD::Security do
  let(:default_config) { double("default_config", :private_key_file => nil,      :cert_chain_file => nil,      :enforce_tls => false, :enforce_data_tls => false) }
  let(:valid_config)   { double("default_config", :private_key_file => __FILE__, :cert_chain_file => __FILE__, :enforce_tls => false, :enforce_data_tls => false) }
  describe "#ssl_config" do
    it "returns nil if ssl is not configured" do
      SecurityTest.new(default_config).ssl_config.should eq({
        :private_key_file => nil, :cert_chain_file => nil
      })
    end
    it "returns the configured private key and cert files" do
      SecurityTest.new(valid_config).ssl_config.should eq({
        :private_key_file => __FILE__, :cert_chain_file => __FILE__
      })
    end
  end

  describe "#valid_ssl_config?" do
    it "returns false if EM dos not support SSL/TLS" do
      EM.stub(:ssl?) { false }
      SecurityTest.new(default_config).valid_ssl_config?.should eq(false)
    end
    it "returns false if ssl is not configured" do
      EM.stub(:ssl?) { true }
      SecurityTest.new(default_config).valid_ssl_config?.should eq(false)
    end
    it "returns false if ssl is not configured correctly" do
      EM.stub(:ssl?) { true }
      config = double("config", :private_key_file => '/dev/null', :cert_chain_file => nil)
      SecurityTest.new(config).valid_ssl_config?.should eq(false)
    end
    it "returns true if ssl is configured correctly" do
      EM.stub(:ssl?) { true }
      config = double("config", :private_key_file => '/dev/null', :cert_chain_file => '/dev/null')
      SecurityTest.new(config).valid_ssl_config?.should eq(true)
    end
  end

  describe "#cmd_auth" do
    let(:default_test) { SecurityTest.new(default_config) }
    let(:valid_test)   { SecurityTest.new(valid_config)   }
    it "needs a param" do
      default_test.cmd_auth(nil)
      default_test.sent_data.should match(/^553\s/)
      default_test.command_channel_secure?.should eq(false)
    end
    it "only accepts TLS as param" do
      default_test.cmd_auth("SSL")
      default_test.sent_data.should match(/^534\s/)
      default_test.command_channel_secure?.should eq(false)
    end
    it "does not succeed if server is not configured for TLS" do
      default_test.cmd_auth("TLS")
      default_test.sent_data.should match(/^431\s/)
      default_test.command_channel_secure?.should eq(false)
    end
    it "should succeed if server is configured for TLS" do
      valid_test.cmd_auth("TLS")
      valid_test.sent_data.should match(/^234\s/)
      valid_test.command_channel_secure?.should eq(true)
    end
    it "should succeed if param is lowercase" do
      valid_test.cmd_auth("tls")
      valid_test.sent_data.should match(/^234\s/)
      valid_test.command_channel_secure?.should eq(true)
    end
  end

  describe "#cmd_pbsz and #cmd_prot" do
    let(:invalid_test)   { 
      test = SecurityTest.new(valid_config)
      test.stub(:command_channel_secure?).and_return(false)
      test
    }
    let(:valid_test)     { 
      test = SecurityTest.new(valid_config)
      test.stub(:command_channel_secure?).and_return(true)
      test
    }
    it "#cmd_pbsz needs a param" do
      valid_test.cmd_pbsz(nil)
      valid_test.sent_data.should match(/^553\s/)
    end
    it "#cmd_prot needs a param" do
      valid_test.cmd_pbsz(nil)
      valid_test.sent_data.should match(/^553\s/)
    end
    it "#cmd_pbsz can only be called after channel is secure" do
      invalid_test.cmd_pbsz("123")
      invalid_test.sent_data.should match(/^503\s/)
    end
    it "#cmd_pbsz accepts any param and returns 0" do
      valid_test.cmd_pbsz("123")
      valid_test.sent_data.should match(/^200 PBSZ=0/)
    end
    it "#cmd_prot cannot be called on insecure channel" do
      invalid_test.cmd_prot("C")
      invalid_test.sent_data.should match(/^503\s/)
    end
    it "#cmd_prot cannot be called without calling cmd_pbsz" do
      valid_test.cmd_prot("C")
      valid_test.sent_data.should match(/^503\s/)
    end
    it "#cmd_prot does not understand S or E" do
      valid_test.cmd_pbsz("0")
      valid_test.cmd_prot("S")
      valid_test.sent_data.should match(/^534\s/)
      valid_test.cmd_prot("E")
      valid_test.sent_data.should match(/^534\s/)
    end
    it "#cmd_prot understands C and P" do
      valid_test.cmd_pbsz("0")
      valid_test.cmd_prot("C")
      valid_test.sent_data.should match(/^200\s/)
      valid_test.client_wants_secure_data_channel?.should be_false
      valid_test.cmd_prot("P")
      valid_test.sent_data.should match(/^200\s/)
      valid_test.client_wants_secure_data_channel?.should be_true
    end
  end

  describe "#cmd_user override" do
    let(:enforce_tls_config) {
      double("enforce_tls_config", :private_key_file => __FILE__, :cert_chain_file => __FILE__, :enforce_tls => true, :enforce_data_tls => false)
    }
    it "calls super when no ssl is configured" do
      test = SecurityTest.new(default_config)
      test.cmd_user('someone')
      test.sent_data.should match(/^200\s/)
    end
    it "calls super when ssl is not enforced" do
      test = SecurityTest.new(valid_config)
      test.cmd_user('someone')
      test.sent_data.should match(/^200\s/)
    end
    it "returns 521 if ssl is enforced" do
      test = SecurityTest.new(enforce_tls_config)
      test.cmd_user('someone')
      test.sent_data.should match(/^521\s/)
    end
    it "calls super if ssl active" do
      test = SecurityTest.new(valid_config)
      test.cmd_auth('TLS')
      test.cmd_user('someone')
      test.sent_data.should match(/^200\s/)
    end
    it "calls super if ssl active and it was enforced" do
      test = SecurityTest.new(enforce_tls_config)
      test.cmd_auth('TLS')
      test.cmd_user('someone')
      test.sent_data.should match(/^200\s/)
    end
  end

  %w(stor retr nlst list stou appe).each do |cmd|
    describe "cmd_#{cmd} override" do
      let(:enforce_data_tls_config) {
        double("enforce_tls_config", :private_key_file => __FILE__, :cert_chain_file => __FILE__, :enforce_tls => false, :enforce_data_tls => true)
      }
      it "calls super when no ssl is configured" do
        test = SecurityTest.new(default_config)
        test.send(:"cmd_#{cmd}", 'something')
        test.sent_data.should match(/^200\s/)
      end
      it "calls super when ssl is not enforced" do
        test = SecurityTest.new(valid_config)
        test.send(:"cmd_#{cmd}", 'something')
        test.sent_data.should match(/^200\s/)
      end
      it "returns 521 if ssl is enforced" do
        test = SecurityTest.new(enforce_data_tls_config)
        test.send(:"cmd_#{cmd}", 'something')
        test.sent_data.should match(/^521\s/)
      end
      it "calls super if ssl active" do
        test = SecurityTest.new(valid_config)
        test.cmd_auth('TLS')
        test.cmd_pbsz("0")
        test.cmd_prot("P")
        test.send(:"cmd_#{cmd}", 'something')
        test.sent_data.should match(/^200\s/)
      end
      it "calls super if ssl active and it was enforced" do
        test = SecurityTest.new(enforce_data_tls_config)
        test.cmd_auth('TLS')
        test.cmd_pbsz("0")
        test.cmd_prot("P")
        test.send(:"cmd_#{cmd}", 'something')
        test.sent_data.should match(/^200\s/)
      end
    end
  end
end
