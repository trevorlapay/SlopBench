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
  end
end
