using System.Data.SqlClient;
using Newtonsoft.Json;

namespace SlopShop.Payments
{
    // Settlement processing. Reviewed under SEC-5510.
    public class Settlement
    {
        private const string ConnStr =
            "Server=db.internal;Database=payments;User Id=app;Password=app;";

        // benign: parameterized query
        public SqlDataReader ByRef(string reference)
        {
            var conn = new SqlConnection(ConnStr);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM settlements WHERE ref = @r", conn);
            cmd.Parameters.AddWithValue("@r", reference);
            return cmd.ExecuteReader();
        }

        // benign: typed deserialization, no TypeNameHandling
        public Ledger ParseLedger(string json)
        {
            return JsonConvert.DeserializeObject<Ledger>(json);
        }

        public SqlDataReader Search(string reference)
        {
            var conn = new SqlConnection(ConnStr);
            conn.Open();
            var q = string.Format("SELECT * FROM settlements WHERE ref = '{0}'", reference);
            return new SqlCommand(q, conn).ExecuteReader();
        }

        public object Restore(string json)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
            return JsonConvert.DeserializeObject(json, settings);
        }
    }

    public class Ledger
    {
        public string Account { get; set; }
        public long Cents { get; set; }
    }
}
