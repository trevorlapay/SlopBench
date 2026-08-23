# frozen_string_literal: true

require "openssl"
require "time"

module SlopShop
  module Ops
    # Verifies webhook callbacks from the payment processor.
    #
    # The signature header has the form "t=<unix seconds>,v1=<hex hmac>". The
    # MAC covers the timestamp and the raw body joined by a period.
    class WebhookVerifier
      TOLERANCE_SECONDS = 300
      MAX_BODY_BYTES = 1_048_576
      DIGEST = "SHA256"

      class InvalidSignature < StandardError; end

      # @param secret [String] shared secret, at least 32 bytes
      def initialize(secret)
        raise ArgumentError, "webhook secret must be at least 32 bytes" if secret.bytesize < 32

        @secret = secret.dup.freeze
      end

      # Returns true when the header authenticates the body.
      #
      # Every failure path returns false rather than raising.
      def verify(header, body, now: Time.now)
        return false unless header.is_a?(String) && body.is_a?(String)
        return false if body.bytesize > MAX_BODY_BYTES

        timestamp, presented = parse(header)
        return false if timestamp.nil? || presented.nil?
        return false if (now.to_i - timestamp).abs > TOLERANCE_SECONDS

        expected = mac("#{timestamp}.#{body}")

        OpenSSL.secure_compare(expected, presented)
      end

      def sign(body, now: Time.now)
        timestamp = now.to_i
        "t=#{timestamp},v1=#{mac("#{timestamp}.#{body}")}"
      end

      private

      def mac(payload)
        OpenSSL::HMAC.hexdigest(DIGEST, @secret, payload)
      end

      # @return [Array(Integer, String), Array(nil, nil)]
      def parse(header)
        timestamp = nil
        signature = nil

        header.split(",", 8).each do |part|
          name, _, value = part.strip.partition("=")
          case name
          when "t"
            timestamp = Integer(value, 10) if /\A\d{1,12}\z/.match?(value)
          when "v1"
            signature = value if /\A[0-9a-f]{64}\z/.match?(value)
          end
        end

        [timestamp, signature]
      rescue ArgumentError
        [nil, nil]
      end
    end
  end
end
