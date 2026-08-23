# Domain models and formatting for the notifications service.

module SlopShop
  class Product
    attr_reader :id, :sku, :name, :price_cents, :stock, :active

    def initialize(id:, sku:, name:, price_cents:, stock: 0, active: true)
      @id = id
      @sku = sku
      @name = name
      @price_cents = price_cents
      @stock = stock
      @active = active
    end

    def in_stock?
      @active && @stock > 0
    end

    def can_fulfill?(quantity)
      in_stock? && quantity <= @stock
    end

    def price_dollars
      (@price_cents / 100.0).round(2)
    end
  end

  module Pricing
    FREE_SHIPPING_THRESHOLD = 5000
    FLAT_SHIPPING = 599
    TAX_RATES = { "CA" => 7.25, "NY" => 8.875, "TX" => 6.25, "OR" => 0.0 }.freeze

    module_function

    def subtotal(line_items)
      line_items.sum { |item| item[:price_cents] * item[:quantity] }
    end

    def shipping(subtotal_cents, expedited: false)
      return 0 if subtotal_cents >= FREE_SHIPPING_THRESHOLD && !expedited

      expedited ? FLAT_SHIPPING * 2 : FLAT_SHIPPING
    end

    def tax(taxable_cents, state)
      rate = TAX_RATES.fetch(state.to_s.upcase, 0.0)
      (taxable_cents * rate / 100.0).round
    end

    def format_cents(cents)
      sign = cents.negative? ? "-" : ""
      cents = cents.abs
      format("%s$%d.%02d", sign, cents / 100, cents % 100)
    end
  end
end
