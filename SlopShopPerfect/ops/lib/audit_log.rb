# frozen_string_literal: true

require "json"
require "securerandom"
require "time"

module SlopShop
  module Ops
    # Append-only operational audit log.
    #
    # Records are single-line JSON with a fixed set of field names.
    class AuditLog
      MAX_FIELD_CHARS = 512

      # Fields that are recorded for every event.
      REQUIRED_FIELDS = %i[actor action subject outcome].freeze

      # Values that are never written, whatever the caller passes.
      REDACTED_KEYS = %w[password secret token key authorization cookie].freeze

      REDACTION = "[redacted]"

      def initialize(io)
        @io = io
        @mutex = Mutex.new
      end

      # Writes one event.
      #
      # @param actor [String] operator or service that acted
      # @param action [String] verb, e.g. "credential.rotate"
      # @param subject [String] what was acted upon
      # @param outcome [String] "success" or "failure"
      # @param details [Hash] extra context; keys naming a secret are redacted
      def record(actor:, action:, subject:, outcome:, **details)
        event = {
          "id" => SecureRandom.uuid,
          "at" => Time.now.utc.iso8601(3),
          "actor" => truncate(actor),
          "action" => truncate(action),
          "subject" => truncate(subject),
          "outcome" => outcome == "success" ? "success" : "failure",
          "details" => sanitise(details)
        }

        line = JSON.generate(event)

        @mutex.synchronize do
          @io.puts(line)
          @io.flush
        end

        event
      end

      private

      def truncate(value)
        text = value.to_s
        text.length > MAX_FIELD_CHARS ? "#{text[0, MAX_FIELD_CHARS]}..." : text
      end

      # Masks any key whose name suggests it carries a credential, and bounds
      # every value. Nested hashes are handled one level down.
      def sanitise(details, depth: 0)
        details.each_with_object({}) do |(key, value), out|
          name = key.to_s
          out[name] =
            if REDACTED_KEYS.any? { |needle| name.downcase.include?(needle) }
              REDACTION
            elsif value.is_a?(Hash) && depth.zero?
              sanitise(value, depth: 1)
            else
              truncate(value)
            end
        end
      end
    end
  end
end
