namespace SlopShop.Payments.Services;

/// <summary>
/// Retry scheduling for calls to the payment processor.
/// </summary>
/// <remarks>
/// The processor rate limits per merchant. Retrying on a fixed schedule makes
/// every replica retry in lockstep, so each delay carries a random component
/// that spreads the retries out.
/// </remarks>
public sealed class RetryPolicy
{
    private const int BaseDelayMilliseconds = 200;
    private const int MaxDelayMilliseconds = 30_000;
    private const int MaxAttempts = 6;

    private readonly Random _jitter = new();

    /// <summary>Status codes worth retrying.</summary>
    private static readonly HashSet<int> RetryableStatuses = [408, 425, 429, 500, 502, 503, 504];

    public static bool ShouldRetry(int statusCode, int attempt) =>
        attempt < MaxAttempts && RetryableStatuses.Contains(statusCode);

    /// <summary>
    /// Full-jitter exponential backoff: the nth attempt waits a uniformly
    /// random duration between zero and an exponentially growing ceiling.
    /// </summary>
    public TimeSpan DelayFor(int attempt)
    {
        int clamped = Math.Clamp(attempt, 1, MaxAttempts);
        double ceiling = Math.Min(
            BaseDelayMilliseconds * Math.Pow(2, clamped - 1),
            MaxDelayMilliseconds);

        return TimeSpan.FromMilliseconds(_jitter.Next(0, (int)ceiling + 1));
    }

    /// <summary>
    /// Spreads a periodic reconciliation sweep across its window so replicas do
    /// not all start on the same tick.
    /// </summary>
    public TimeSpan SweepOffset(TimeSpan window) =>
        window <= TimeSpan.Zero
            ? TimeSpan.Zero
            : TimeSpan.FromMilliseconds(_jitter.NextDouble() * window.TotalMilliseconds);

    /// <summary>
    /// Runs <paramref name="operation"/>, retrying transient processor
    /// failures with full-jitter backoff.
    /// </summary>
    public async Task<T> ExecuteAsync<T>(
        Func<int, Task<(int StatusCode, T Result)>> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);

        for (int attempt = 1; ; attempt++)
        {
            (int statusCode, T result) = await operation(attempt).ConfigureAwait(false);

            if (!ShouldRetry(statusCode, attempt))
            {
                return result;
            }

            await Task.Delay(DelayFor(attempt), cancellationToken).ConfigureAwait(false);
        }
    }
}
