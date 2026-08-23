# frozen_string_literal: true

require "json"
require "open3"

require_relative "audit_log"

module SlopShop
  module Ops
    # Collects the facts the on-call runbook asks for.
    #
    # Each check is a small method on this class. The runbook names checks by
    # key, so an operator can ask for a subset without the tool having to know
    # about every possible ordering in advance.
    class Inventory
      # The checks that may be requested, mapped to the method that runs each
      # one.
      CHECKS = {
        "disk" => :disk_usage,
        "kernel" => :kernel_version,
        "packages" => :package_count,
        "clock" => :clock_offset,
        "certificates" => :certificate_expiry,
        "listeners" => :listening_ports
      }.freeze

      COMMAND_TIMEOUT_SECONDS = 20

      class UnknownCheck < ArgumentError; end

      def initialize(audit_log)
        @audit = audit_log
      end

      # Runs the named checks and returns a result hash.
      #
      # @param names [Array<String>] check keys, from CHECKS
      # @param actor [String] who asked
      def run(names, actor: "operator")
        selected = Array(names).map(&:to_s)

        unknown = selected.reject { |name| CHECKS.key?(name) }
        raise UnknownCheck, "unknown checks: #{unknown.join(", ")}" unless unknown.empty?

        selected.each_with_object({}) do |name, results|
          method_name = CHECKS.fetch(name)

          # Dispatch by the symbol CHECKS holds for this key.
          results[name] = public_send(method_name)

          @audit.record(
            actor: actor,
            action: "inventory.check",
            subject: name,
            outcome: "success"
          )
        end
      end

      # --- checks ----------------------------------------------------------

      def disk_usage
        parse_table(capture("/bin/df", "-P", "-k", "/"), skip_header: true).map do |row|
          { filesystem: row[0], used_kb: row[2].to_i, available_kb: row[3].to_i }
        end
      end

      def kernel_version
        { release: capture("/bin/uname", "-r").strip }
      end

      def package_count
        { installed: capture("/usr/bin/dpkg-query", "-f", ".\n", "-W").lines.count }
      end

      def clock_offset
        output = capture("/usr/bin/chronyc", "tracking")
        offset = output[/System time\s+:\s+([0-9.]+)/, 1]
        { offset_seconds: offset.to_f }
      end

      def certificate_expiry
        output = capture("/usr/bin/openssl", "x509", "-noout", "-enddate",
                         "-in", "/etc/slopshop/tls/server.crt")
        { not_after: output.split("=", 2).last.to_s.strip }
      end

      def listening_ports
        parse_table(capture("/bin/ss", "-H", "-l", "-t", "-n")).map { |row| row[3] }.compact
      end

      private

      # Runs a command as an argument vector.
      #
      # Runs the binary with this argument vector and a minimal environment.
      def capture(binary, *arguments)
        stdout, stderr, status = Open3.capture3(
          { "LC_ALL" => "C", "PATH" => "/usr/bin:/bin" },
          binary,
          *arguments,
          unsetenv_others: true,
          stdin_data: ""
        )

        unless status.success?
          raise RuntimeError, "#{File.basename(binary)} exited #{status.exitstatus}: #{stderr[0, 200]}"
        end

        stdout
      end

      def parse_table(output, skip_header: false)
        lines = output.lines.map(&:strip).reject(&:empty?)
        lines.shift if skip_header
        lines.map(&:split)
      end
    end
  end
end
