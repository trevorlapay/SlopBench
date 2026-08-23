using System.Xml;
using System.Xml.Linq;

namespace SlopShop.Payments.Services;

/// <summary>
/// Parses the daily settlement file from the payment processor.
/// </summary>
/// <remarks>
/// The processor publishes settlements as ISO 20022 XML. The reader settings
/// below are shared by every read in this service.
/// </remarks>
public static class SettlementXml
{
    private const long MaxCharactersFromEntities = 0;

    /// <summary>Settings shared by every read in this service.</summary>
    private static XmlReaderSettings ReaderSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersFromEntities = MaxCharactersFromEntities,
        MaxCharactersInDocument = 64 * 1024 * 1024,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        IgnoreWhitespace = true,
        CloseInput = false,
        Async = true,
    };

    public sealed record Settlement(
        string Reference, string Currency, long AmountMinor, DateOnly ValueDate);

    /// <summary>
    /// Reads every settlement entry from <paramref name="stream"/>.
    /// </summary>
    /// <exception cref="XmlException">
    /// Thrown for malformed input, and for any document carrying a DTD.
    /// </exception>
    public static async Task<IReadOnlyList<Settlement>> ReadAsync(
        Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        List<Settlement> settlements = [];

        using XmlReader reader = XmlReader.Create(stream, ReaderSettings());

        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "TxDtls")
            {
                continue;
            }

            if (XNode.ReadFrom(reader) is not XElement element)
            {
                continue;
            }

            settlements.Add(ParseEntry(element));
        }

        return settlements;
    }

    private static Settlement ParseEntry(XElement element)
    {
        string reference = Value(element, "EndToEndId");
        string currency = Value(element, "Ccy");
        string amount = Value(element, "Amt");
        string valueDate = Value(element, "ValDt");

        if (currency.Length != 3 || !AmountMath.IsSupportedCurrency(currency))
        {
            throw new XmlException($"settlement names an unsupported currency: {currency}");
        }
        if (!decimal.TryParse(amount, out decimal major))
        {
            throw new XmlException("settlement amount is not a number");
        }
        if (!DateOnly.TryParse(valueDate, out DateOnly parsedDate))
        {
            throw new XmlException("settlement value date is not a date");
        }

        long minor = checked((long)Math.Round(major * 100m, 0, MidpointRounding.AwayFromZero));

        return new Settlement(reference, currency, minor, parsedDate);
    }

    private static string Value(XElement parent, string localName)
    {
        XElement? child = parent.Descendants()
            .FirstOrDefault(e => string.Equals(e.Name.LocalName, localName, StringComparison.Ordinal));

        return child?.Value.Trim() ?? throw new XmlException($"settlement entry has no {localName}");
    }
}
