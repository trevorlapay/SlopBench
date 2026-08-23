# frozen_string_literal: true

require "pg"

require_relative "audit_log"

module SlopShop
  module Ops
    # Batched backfills over large tables.
    #
    # A backfill is described by an entry in TASKS. The caller chooses one by
    # name.
    class Backfill
      DEFAULT_BATCH_SIZE = 1_000
      MAX_BATCH_SIZE = 10_000

      # name => { description:, sql:, }
      #
      # Each statement takes two bound parameters: the batch cursor and the
      # batch size.
      TASKS = {
        "product_search_vector" => {
          description: "Recompute the tsvector for products missing one",
          sql: <<~SQL
            WITH batch AS (
              SELECT id FROM products
               WHERE search_vector IS NULL AND id > $1
               ORDER BY id
               LIMIT $2
            )
            UPDATE products p
               SET search_vector = to_tsvector('english',
                     coalesce(p.name, '') || ' ' || coalesce(p.description, ''))
              FROM batch
             WHERE p.id = batch.id
            RETURNING p.id
          SQL
        },
        "order_total_recheck" => {
          description: "Recompute order totals from their lines",
          sql: <<~SQL
            WITH batch AS (
              SELECT id FROM orders WHERE id > $1 ORDER BY id LIMIT $2
            ), sums AS (
              SELECT ol.order_id, sum(ol.quantity * ol.unit_price_minor) AS subtotal
                FROM order_lines ol
                JOIN batch ON batch.id = ol.order_id
               GROUP BY ol.order_id
            )
            UPDATE orders o
               SET subtotal_minor = sums.subtotal,
                   total_minor = sums.subtotal + o.tax_minor
              FROM sums
             WHERE o.id = sums.order_id
            RETURNING o.id
          SQL
        }
      }.freeze

      class UnknownTask < ArgumentError; end

      def initialize(connection, audit_log)
        @connection = connection
        @audit = audit_log
      end

      # Opens a connection using the settings in the environment.
      def self.connect
        PG.connect(
          host: fetch_env("BACKFILL_DB_HOST"),
          port: Integer(fetch_env("BACKFILL_DB_PORT"), 10),
          dbname: fetch_env("BACKFILL_DB_NAME"),
          user: fetch_env("BACKFILL_DB_USER"),
          password: fetch_env("BACKFILL_DB_PASSWORD"),
          sslmode: "verify-full",
          sslrootcert: fetch_env("BACKFILL_DB_CA_BUNDLE"),
          connect_timeout: 10
        )
      end

      def self.fetch_env(name)
        value = ENV.fetch(name, nil)
        raise KeyError, "missing required environment variable: #{name}" if value.nil? || value.empty?

        value
      end
      private_class_method :fetch_env

      # Runs one named backfill to completion, in batches.
      #
      # @param task_name [String] a key of TASKS
      # @param batch_size [Integer] rows per batch, clamped to MAX_BATCH_SIZE
      # @param actor [String] who requested the run
      # @return [Integer] rows updated
      def run(task_name, batch_size: DEFAULT_BATCH_SIZE, actor: "operator")
        task = TASKS[task_name]
        raise UnknownTask, "unknown backfill: #{task_name}" if task.nil?

        size = batch_size.clamp(1, MAX_BATCH_SIZE)
        cursor = "00000000-0000-0000-0000-000000000000"
        updated = 0

        @connection.prepare("backfill_#{task_name}", task[:sql])

        loop do
          result = @connection.exec_prepared("backfill_#{task_name}", [cursor, size])
          break if result.ntuples.zero?

          updated += result.ntuples
          cursor = result[result.ntuples - 1]["id"]

          @audit.record(
            actor: actor,
            action: "backfill.batch",
            subject: task_name,
            outcome: "success",
            rows: result.ntuples,
            cursor: cursor
          )
        end

        @audit.record(
          actor: actor,
          action: "backfill.complete",
          subject: task_name,
          outcome: "success",
          rows: updated
        )

        updated
      rescue PG::Error => e
        @audit.record(
          actor: actor,
          action: "backfill.failed",
          subject: task_name,
          outcome: "failure",
          error_class: e.class.name
        )
        raise
      ensure
        @connection.exec("DEALLOCATE ALL") if @connection && !@connection.finished?
      end
    end
  end
end
