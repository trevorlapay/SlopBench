# Notification text/date formatting helpers.

module SlopShop
  module Formatter
    module_function

    def humanize_status(status)
      status.to_s.tr("_", " ").split.map(&:capitalize).join(" ")
    end

    def order_summary(order)
      lines = order[:items].map do |item|
        format("  %<qty>d x %<name>s", qty: item[:quantity], name: item[:name])
      end
      header = "Order ##{order[:id]} (#{humanize_status(order[:status])})"
      ([header] + lines).join("\n")
    end

    def truncate(text, length = 80)
      return text if text.length <= length

      "#{text[0, length - 1].rstrip}…"
    end

    def pluralize(count, singular, plural = nil)
      plural ||= "#{singular}s"
      "#{count} #{count == 1 ? singular : plural}"
    end

    def relative_time(seconds_ago)
      case seconds_ago
      when 0...60 then "just now"
      when 60...3600 then pluralize(seconds_ago / 60, "minute") + " ago"
      when 3600...86_400 then pluralize(seconds_ago / 3600, "hour") + " ago"
      else pluralize(seconds_ago / 86_400, "day") + " ago"
      end
    end

    def format_cents(cents)
      sign = cents.negative? ? "-" : ""
      cents = cents.abs
      format("%s$%d.%02d", sign, cents / 100, cents % 100)
    end

    def subject_for(kind)
      subjects = {
        order_confirmation: "Your SlopShop order is confirmed",
        shipping_notice: "Your SlopShop order has shipped",
        refund_notice: "Your SlopShop refund has been issued"
      }
      subjects.fetch(kind.to_sym) { raise KeyError, "no subject for #{kind}" }
    end

    def address_line(address)
      parts = [address[:line1], address[:line2], address[:city], address[:postal_code]]
      parts.reject { |part| part.nil? || part.empty? }.join(", ")
    end

    def tracking_line(shipment)
      return "Tracking is not available yet." if shipment[:tracking].to_s.empty?

      "Tracking #{shipment[:tracking]} with #{shipment[:carrier]}."
    end

    def bullet_list(entries)
      entries.map { |entry| "  - #{entry}" }.join("\n")
    end
  end
end
