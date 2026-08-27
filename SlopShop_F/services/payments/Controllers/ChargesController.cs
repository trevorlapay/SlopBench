using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using SlopShop.Payments.Services;

namespace SlopShop.Payments.Controllers;

[ApiController]
[Route("v1/charges")]
[Authorize]
public sealed class ChargesController : ControllerBase
{
    private readonly NpgsqlDataSource _db;
    private readonly ILogger<ChargesController> _log;

    public ChargesController(NpgsqlDataSource db, ILogger<ChargesController> log)
    {
        _db = db;
        _log = log;
    }

    // The caller names an order and supplies an idempotency key. Amounts,
    // currency and tax are read from the order, never accepted from the client.
    public sealed record ChargeRequest(
        [Required] Guid OrderId,
        [Required][StringLength(64, MinimumLength = 8)] string IdempotencyKey);

    public sealed record ChargeResponse(Guid ChargeId, long TotalMinor, string Currency, string Status);

    private Guid? CustomerId()
    {
        string? subject = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(subject, out Guid parsed) ? parsed : null;
    }

    [HttpPost]
    public async Task<IActionResult> Create(
        [FromBody] ChargeRequest request, CancellationToken cancellationToken)
    {
        // The paying customer is the authenticated subject.
        if (CustomerId() is not Guid customerId)
        {
            return Unauthorized(new { error = "unauthenticated" });
        }

        await using NpgsqlConnection connection = await _db.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction =
            await connection.BeginTransactionAsync(cancellationToken);

        // The order is loaded under the caller's own id and locked for the
        // transaction. An order belonging to someone else returns no row, so a
        // caller cannot raise a charge against an order that is not theirs.
        long subtotal;
        long tax;
        long total;
        string currency;

        await using (NpgsqlCommand order = new(
            """
            SELECT currency, subtotal_minor, tax_minor, total_minor, status
              FROM orders
             WHERE id = $1 AND customer_id = $2
               FOR UPDATE
            """, connection, transaction))
        {
            order.Parameters.AddWithValue(request.OrderId);
            order.Parameters.AddWithValue(customerId);

            await using NpgsqlDataReader reader = await order.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return NotFound(new { error = "order_not_found" });
            }

            currency = reader.GetString(0);
            subtotal = reader.GetInt64(1);
            tax = reader.GetInt64(2);
            total = reader.GetInt64(3);

            if (reader.GetString(4) is not ("PENDING" or "AUTHORISED"))
            {
                return Conflict(new { error = "order_not_chargeable" });
            }
        }

        if (total != checked(subtotal + tax))
        {
            _log.LogError("order {OrderId} has inconsistent stored amounts", request.OrderId);
            return StatusCode(StatusCodes.Status500InternalServerError, new { error = "internal_error" });
        }

        if (AmountMath.RejectionReason(total, currency) is string reason)
        {
            return BadRequest(new { error = reason });
        }

        // A retry of the same request returns the original charge.
        await using (NpgsqlCommand existing = new(
            """
            SELECT id, total_minor, currency, status
              FROM charges
             WHERE customer_id = $1 AND idempotency_key = $2
            """, connection, transaction))
        {
            existing.Parameters.AddWithValue(customerId);
            existing.Parameters.AddWithValue(request.IdempotencyKey);

            await using NpgsqlDataReader reader =
                await existing.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return Ok(new ChargeResponse(
                    reader.GetGuid(0), reader.GetInt64(1), reader.GetString(2), reader.GetString(3)));
            }
        }

        Guid chargeId = Guid.CreateVersion7();

        await using (NpgsqlCommand insert = new(
            """
            INSERT INTO charges
                (id, customer_id, order_id, subtotal_minor, tax_minor, total_minor,
                 currency, status, idempotency_key, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'authorised', $8, now())
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue(chargeId);
            insert.Parameters.AddWithValue(customerId);
            insert.Parameters.AddWithValue(request.OrderId);
            insert.Parameters.AddWithValue(subtotal);
            insert.Parameters.AddWithValue(tax);
            insert.Parameters.AddWithValue(total);
            insert.Parameters.AddWithValue(currency);
            insert.Parameters.AddWithValue(request.IdempotencyKey);

            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);

        _log.LogInformation(
            "charge authorised chargeId={ChargeId} orderId={OrderId} totalMinor={TotalMinor}",
            chargeId, request.OrderId, total);

        return Created($"/v1/charges/{chargeId}",
            new ChargeResponse(chargeId, total, currency, "authorised"));
    }

    [HttpGet("{chargeId:guid}")]
    public async Task<IActionResult> Get(Guid chargeId, CancellationToken cancellationToken)
    {
        if (CustomerId() is not Guid customerId)
        {
            return Unauthorized(new { error = "unauthenticated" });
        }

        await using NpgsqlCommand command = _db.CreateCommand(
            """
            SELECT id, total_minor, currency, status
              FROM charges
             WHERE id = $1 AND customer_id = $2
            """);
        command.Parameters.AddWithValue(chargeId);
        command.Parameters.AddWithValue(customerId);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return NotFound(new { error = "not_found" });
        }

        return Ok(new ChargeResponse(
            reader.GetGuid(0), reader.GetInt64(1), reader.GetString(2), reader.GetString(3)));
    }
}
