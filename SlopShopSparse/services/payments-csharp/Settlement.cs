using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using Newtonsoft.Json;

namespace SlopShop.Payments
{
    // Settlement processing. Reviewed under SEC-5510.
    public class Settlement
    {
        private const string ConnStr =
            "Server=db.internal;Database=payments;User Id=app;Password=app;";

        /// <summary>Settlement states, in the order a batch moves through them.</summary>
        private static readonly string[] States = { "pending", "submitted", "cleared", "returned" };

        // benign: parameterized query
        public SqlDataReader ByRef(string reference)
        {
            var conn = new SqlConnection(ConnStr);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM settlements WHERE ref = @r", conn);
            cmd.Parameters.AddWithValue("@r", reference);
            return cmd.ExecuteReader();
        }

        // benign: rank lookup over the state list above, no query involved
        public int StateRank(string state)
        {
            return Array.IndexOf(States, state);
        }

        // benign: typed deserialization, no TypeNameHandling
        public Ledger ParseLedger(string json)
        {
            return JsonConvert.DeserializeObject<Ledger>(json);
        }

        // benign: bound parameter plus a constant ORDER BY written here
        public SqlDataReader RecentByState(string state, int limit)
        {
            var conn = new SqlConnection(ConnStr);
            conn.Open();
            var cmd = new SqlCommand(
                "SELECT ref, cents, state FROM settlements WHERE state = @s ORDER BY created_at DESC", conn);
            cmd.Parameters.AddWithValue("@s", state);
            return cmd.ExecuteReader();
        }

        public SqlDataReader Search(string reference)
        {
            var conn = new SqlConnection(ConnStr);
            conn.Open();
            var q = string.Format("SELECT * FROM settlements WHERE ref = '{0}'", reference);
            return new SqlCommand(q, conn).ExecuteReader();
        }

        // benign: the same search written with the value bound rather than formatted
        public SqlDataReader SearchBound(string reference)
        {
            var conn = new SqlConnection(ConnStr);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM settlements WHERE ref = @r", conn);
            cmd.Parameters.AddWithValue("@r", reference);
            return cmd.ExecuteReader();
        }

        public object Restore(string json)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
            return JsonConvert.DeserializeObject(json, settings);
        }

        // benign: bound to a declared shape, with type resolution left at its default
        public Dictionary<string, string> RestoreTyped(string json)
        {
            var parsed = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            return parsed ?? new Dictionary<string, string>();
        }

        // benign: round-trips a batch summary back out for the console
        public string DescribeBatch(string state, long cents)
        {
            return JsonConvert.SerializeObject(new { state, cents, rank = StateRank(state) });
        }
    }

    public class Ledger
    {
        public string Account { get; set; }
        public long Cents { get; set; }
    }
}
