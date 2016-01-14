# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/timestamp"
require "socket"
require "json"

# Read events from github webhooks
class LogStash::Inputs::GitHub < LogStash::Inputs::Base
  config_name "github"

  # The ip to listen on
  config :ip, :validate => :string, :default => "0.0.0.0"

  # The port to listen on
  config :port, :validate => :number, :required => true

  # Your GitHub Secret Token for the webhook
  config :secret_token, :validate => :string, :required => false

  # If Secret is defined, we drop the events that don't match. 
  # Otherwise, we'll just add a invalid tag
  config :drop_invalid, :validate => :boolean

  def register
    require "ftw"
  end # def register


  public
  def run(output_queue)
    @server = FTW::WebServer.new(@ip, @port) do |request, response|
        body = request.read_body
        begin
          parsed_body = JSON.parse(body)
          ts = parsed_body["repository"]["created_at"]
          if ts
            parsed_body["repository"]["created_at"] = init_timestamp(ts) ? init_timestamp(ts) : "" + ts.to_s
          end
          ts = parsed_body["repository"]["pushed_at"]
          if ts
            parsed_body["repository"]["pushed_at"] = init_timestamp(ts) ? init_timestamp(ts) : "" + ts.to_s
          end
          ts = parsed_body["repository"]["updated_at"]
          if ts
            parsed_body["repository"]["updated_at"] = init_timestamp(ts) ? init_timestamp(ts) : "" + ts.to_s
          end
          event = LogStash::Event.new(parsed_body)
        rescue JSON::ParserError => e
          @logger.info("JSON parse failure. Falling back to plain-text", :error => e, :data => body)
          event = LogStash::Event.new("message" => body, "tags" => "_invalidjson")
        end
        event['headers'] = request.headers.to_hash
        if defined? @secret_token and event['headers']['x-hub-signature']
            event['hash'] = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), @secret_token, body)
            if not Rack::Utils.secure_compare(event['hash'], event['headers']['x-hub-signature'])
                if not @drop_invalid
                    event['tags'] = "_Invalid_Github_Message"
                else
                    @logger.info("Dropping invalid Github message")
                    drop = true
                end
            end
        end
        if not drop
            decorate(event)
            output_queue << event
        end
        response.status = 200
        response.body = "Accepted!"
    end
    @server.run
  end # def run

  def init_timestamp(o)
    begin
      timestamp = LogStash::Timestamp.coerce(o)
      return timestamp if timestamp
    rescue LogStash::TimestampParserError => e
    end
  end


  def close
    @server.stop
  end # def close

end # class LogStash::Inputs::Github
