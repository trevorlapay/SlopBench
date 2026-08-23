using System.Text;
using Npgsql;

namespace SlopShop.Payments.Services;

/// <summary>
/// Reconciliation reads over the charge ledger.
/// </summary>
/// <remarks>
/// The finance console lets an operator choose a sort order and a set of status
/// filters. The ORDER BY fragment is selected from the table below by key.
/// </remarks>
public sealed class LedgerQuery
{
    /// <summary>
    /// Sort keys the console offers, mapped to the ORDER BY fragment each one
    /// stands for.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> Orderings =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["newest"] = "created_at DESC, id ASC",
            ["oldest"] = "created_at ASC, id ASC",
            ["largest"] = "total_minor DESC, id ASC",
            ["smallest"] = "total_minor ASC, id ASC",
            ["by_status"] = "status ASC, created_at DESC, id ASC",
        };

    private static readonly HashSet<string> KnownStatuses =
        new(StringComparer.Ordinal) { "authorised", "captured", "failed", "refunded" };

    private const int MaxPageSize = 500;

    private readonly NpgsqlDataSource _db;

    public LedgerQuery(NpgsqlDataSource db) => _db = db;

    public sealed record LedgerRow(
        Guid Id, Guid OrderId, long TotalMinor, string Currency, string Status, DateTime CreatedAt);

    /// <summary>
    /// Returns one page of the ledger.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// Thrown when the sort key is not one of <see cref="Orderings"/>, or when a
    /// status is not one the ledger records.
    /// </exception>
    public async Task<IReadOnlyList<LedgerRow>> PageAsync(
        string sortKey,
        IReadOnlyCollection<string> statuses,
        DateOnly from,
        DateOnly to,
        int limit,
        int offset,
        CancellationToken cancellationToken)
    {
        if (!Orderings.TryGetValue(sortKey, out string? orderBy))
        {
            throw new ArgumentException($"unsupported sort key: {sortKey}", nameof(sortKey));
        }

        foreach (string status in statuses)
        {
            if (!KnownStatuses.Contains(status))
            {
                throw new ArgumentException($"unknown status: {status}", nameof(statuses));
            }
        }

        StringBuilder sql = new(
            """
            SELECT id, order_id, total_minor, currency, status, created_at
              FROM charges
             WHERE created_at >= $1 AND created_at < $2
            """);

        if (statuses.Count > 0)
        {
            // The whole list travels as a single array parameter.
            sql.Append(" AND status = ANY($3)");
        }

        sql.Append(" ORDER BY ").Append(orderBy);
        sql.Append(" LIMIT $4 OFFSET $5");

        await using NpgsqlCommand command = _db.CreateCommand(sql.ToString());
        command.Parameters.AddWithValue(from.ToDateTime(TimeOnly.MinValue));
        command.Parameters.AddWithValue(to.AddDays(1).ToDateTime(TimeOnly.MinValue));
        command.Parameters.AddWithValue(statuses.ToArray());
        command.Parameters.AddWithValue(Math.Clamp(limit, 1, MaxPageSize));
        command.Parameters.AddWithValue(Math.Max(offset, 0));

        List<LedgerRow> rows = [];
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new LedgerRow(
                reader.GetGuid(0),
                reader.GetGuid(1),
                reader.GetInt64(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetDateTime(5)));
        }

        return rows;
    }

    /// <summary>The sort keys the console may offer.</summary>
    public static IEnumerable<string> SupportedSortKeys() => Orderings.Keys;
}
