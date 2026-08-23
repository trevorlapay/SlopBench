namespace SlopShop.Payments.Services;

/// <summary>
/// Money arithmetic for the payments service.
/// </summary>
/// <remarks>
/// Amounts are minor units held in <see cref="long"/>. Arithmetic runs in a
/// checked context.
/// </remarks>
public static class AmountMath
{
    /// <summary>Largest amount the service will authorise, in minor units.</summary>
    public const long MaxChargeMinor = 100_000_00L;

    /// <summary>Currencies the service is configured to settle.</summary>
    private static readonly HashSet<string> SupportedCurrencies =
        new(StringComparer.Ordinal) { "GBP", "EUR", "USD" };

    public static bool IsSupportedCurrency(string currency) =>
        SupportedCurrencies.Contains(currency);

    /// <summary>
    /// Multiplies a unit price by a quantity. Throws
    /// <see cref="OverflowException"/> rather than wrapping.
    /// </summary>
    public static long Extend(long unitPriceMinor, int quantity)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(unitPriceMinor);
        ArgumentOutOfRangeException.ThrowIfLessThan(quantity, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(quantity, 20);

        checked
        {
            return unitPriceMinor * quantity;
        }
    }

    /// <summary>Sums line totals, throwing on overflow or a negative element.</summary>
    public static long Sum(IReadOnlyList<long> amountsMinor)
    {
        ArgumentNullException.ThrowIfNull(amountsMinor);

        long total = 0;
        checked
        {
            foreach (long amount in amountsMinor)
            {
                ArgumentOutOfRangeException.ThrowIfNegative(amount);
                total += amount;
            }
        }
        return total;
    }

    /// <summary>
    /// Applies a tax rate expressed in basis points, rounding half away from
    /// zero. The intermediate product is computed in <see cref="decimal"/>.
    /// </summary>
    public static long ApplyBasisPoints(long amountMinor, int basisPoints)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(amountMinor);
        ArgumentOutOfRangeException.ThrowIfNegative(basisPoints);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(basisPoints, 10_000);

        decimal scaled = (decimal)amountMinor * basisPoints / 10_000m;
        decimal rounded = Math.Round(scaled, 0, MidpointRounding.AwayFromZero);

        checked
        {
            return (long)rounded;
        }
    }

    /// <summary>
    /// Validates a charge request. Returns the reason the amount is
    /// unacceptable, or null when it may proceed.
    /// </summary>
    public static string? RejectionReason(long amountMinor, string currency)
    {
        if (!IsSupportedCurrency(currency))
        {
            return "unsupported_currency";
        }
        if (amountMinor <= 0)
        {
            return "amount_not_positive";
        }
        if (amountMinor > MaxChargeMinor)
        {
            return "amount_above_ceiling";
        }
        return null;
    }
}
