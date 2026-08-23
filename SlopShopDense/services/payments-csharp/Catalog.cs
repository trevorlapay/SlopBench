using System;
using System.Collections.Generic;
using System.Globalization;

namespace SlopShop.Catalog
{
    public sealed class Product
    {
        public long Id { get; }
        public string Sku { get; }
        public string Name { get; }
        public long PriceCents { get; }
        public int Stock { get; }
        public bool Active { get; }

        public Product(long id, string sku, string name, long priceCents, int stock, bool active)
        {
            Id = id;
            Sku = sku;
            Name = name;
            PriceCents = priceCents;
            Stock = stock;
            Active = active;
        }

        public bool InStock() => Active && Stock > 0;

        public bool CanFulfill(int quantity) => InStock() && quantity <= Stock;

        public decimal PriceDollars() => PriceCents / 100m;
    }

    public sealed class PriceCalculator
    {
        private const long FreeShippingThreshold = 5000;
        private const long FlatShipping = 599;

        private static readonly Dictionary<string, double> TaxRates = new()
        {
            ["CA"] = 7.25, ["NY"] = 8.875, ["TX"] = 6.25, ["WA"] = 6.5, ["OR"] = 0.0,
        };

        public long Subtotal(IEnumerable<long> lineTotals)
        {
            long sum = 0;
            foreach (var t in lineTotals) sum += t;
            return sum;
        }

        public long Shipping(long subtotalCents, bool expedited)
        {
            if (subtotalCents >= FreeShippingThreshold && !expedited) return 0;
            return expedited ? FlatShipping * 2 : FlatShipping;
        }

        public long PercentDiscount(long subtotalCents, double percent)
        {
            long raw = (long)Math.Round(subtotalCents * (percent / 100.0));
            return Math.Min(raw, subtotalCents);
        }

        public long Tax(long taxableCents, string state)
        {
            var rate = TaxRates.TryGetValue(state.ToUpperInvariant(), out var r) ? r : 0.0;
            return (long)Math.Round(taxableCents * (rate / 100.0));
        }

        public static string FormatCents(long cents)
        {
            var dollars = cents / 100m;
            return dollars.ToString("C", CultureInfo.GetCultureInfo("en-US"));
        }
    }
}
