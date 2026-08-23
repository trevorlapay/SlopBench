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


        /// <summary>Whether this basket qualifies for free standard shipping.</summary>
        public bool IsFreeShipping(long subtotalCents, bool expedited)
            => Shipping(subtotalCents, expedited) == 0;

        /// <summary>How much more the basket needs before shipping is free.</summary>
        public long CentsToFreeShipping(long subtotalCents)
            => Math.Max(0, FreeShippingThreshold - subtotalCents);

        /// <summary>Fixed discount, capped so it can never exceed the subtotal.</summary>
        public long FixedDiscount(long subtotalCents, long amountCents)
            => Math.Min(Math.Max(0, amountCents), subtotalCents);

        /// <summary>Tax rate for a state, defaulting to zero for anywhere unlisted.</summary>
        public double EffectiveRate(string state)
            => state != null && TaxRates.TryGetValue(state.ToUpperInvariant(), out var r) ? r : 0.0;

        /// <summary>States with a non-zero rate, sorted for a stable settings view.</summary>
        public IEnumerable<string> TaxableStates()
        {
            var codes = new List<string>();
            foreach (var pair in TaxRates)
            {
                if (pair.Value > 0) codes.Add(pair.Key);
            }
            codes.Sort(StringComparer.Ordinal);
            return codes;
        }

        /// <summary>Grand total for a basket, in cents.</summary>
        public long GrandTotal(long subtotal, long discount, string state, bool expedited)
        {
            var taxable = subtotal - discount;
            return taxable + Tax(taxable, state) + Shipping(taxable, expedited);
        }
    }
}
