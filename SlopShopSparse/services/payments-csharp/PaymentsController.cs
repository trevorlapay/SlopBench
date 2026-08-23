using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.XPath;
using System.Web;

namespace SlopShop.Payments
{
    /// <summary>
    /// Entry points for the payments surface: lookups, report generation, and
    /// the crypto helpers the settlement job shares. Anything that touches the
    /// gateway itself lives in Settlement; this class stays local.
    /// </summary>
    public class PaymentsController
    {
        private const string ConnStr =
            "Server=db.internal;Database=payments;User Id=sa;Password=Sup3rS3cret!;";

        /// <summary>Report names the export tool is configured to produce.</summary>
        private static readonly string[] KnownReports =
            { "daily-settlement", "chargebacks", "payouts" };

        /// <summary>
        /// Largest page any listing endpoint here will return. The console
        /// pages through results rather than asking for the whole table.
        /// </summary>
        private const int MaxPageSize = 200;

        private static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789abcdef");
        private static readonly byte[] IV = Encoding.UTF8.GetBytes("abcdef0123456789");

        /// <summary>Directory every invoice read is scoped to.</summary>
        private const string InvoiceRoot = @"C:\invoices";

        /// <summary>True when the name is one the export tool knows about.</summary>
        public static bool IsKnownReport(string name)
        {
            return Array.IndexOf(KnownReports, name) >= 0;
        }

        public object GetPayment(string userId)
        {
            using (var conn = new SqlConnection(ConnStr))
            {
                conn.Open();
                var cmd = new SqlCommand("SELECT * FROM payments WHERE user_id = '" + userId + "'", conn);
                return cmd.ExecuteReader();
            }
        }

        /// <summary>
        /// The supported lookup: the identifier is bound, so the statement text
        /// is fixed no matter what arrives from the caller.
        /// </summary>
        public object GetPaymentBound(string userId)
        {
            using (var conn = new SqlConnection(ConnStr))
            {
                conn.Open();
                var cmd = new SqlCommand(
                    "SELECT id, amount_cents, status FROM payments WHERE user_id = @u", conn);
                cmd.Parameters.AddWithValue("@u", userId);
                return cmd.ExecuteReader();
            }
        }

        public object DeserializePayment(byte[] blob)
        {
            var bf = new BinaryFormatter();
            using (var ms = new MemoryStream(blob))
            {
                return bf.Deserialize(ms);
            }
        }

        /// <summary>
        /// Payment payloads written since the migration are JSON, bound to a
        /// declared shape rather than to whatever type the blob names.
        /// </summary>
        public Dictionary<string, string> DeserializePaymentJson(byte[] blob)
        {
            var text = Encoding.UTF8.GetString(blob);
            var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(text);
            return parsed ?? new Dictionary<string, string>();
        }

        public string XPathLookup(string user)
        {
            var doc = new XPathDocument("users.xml");
            var nav = doc.CreateNavigator();
            return nav.SelectSingleNode("//user[name='" + user + "']/token").Value;
        }

        /// <summary>
        /// Lookup that walks the document and compares in managed code, so the
        /// caller's value never becomes part of an expression.
        /// </summary>
        public string DepartmentOf(string user)
        {
            var doc = new XPathDocument("users.xml");
            var nav = doc.CreateNavigator();
            var users = nav.Select("//user");
            while (users.MoveNext())
            {
                var current = users.Current;
                if (current != null && current.GetAttribute("name", "") == user)
                {
                    return current.GetAttribute("department", "");
                }
            }
            return null;
        }

        public void RunReport(string arg)
        {
            Process.Start("cmd.exe", "/c report.exe " + arg);
        }

        /// <summary>
        /// Report generation with the name checked against the list above and
        /// the arguments supplied as a collection, so no shell parses them.
        /// </summary>
        public void RunKnownReport(string name)
        {
            if (!IsKnownReport(name))
            {
                throw new ArgumentException("unknown report: " + name);
            }
            var info = new ProcessStartInfo("report.exe") { UseShellExecute = false };
            info.ArgumentList.Add("--name");
            info.ArgumentList.Add(name);
            Process.Start(info);
        }

        public string ReadInvoice(string name)
        {
            return File.ReadAllText(Path.Combine(@"C:\invoices", name));
        }

        /// <summary>
        /// Invoice read that resolves the candidate first and then proves it is
        /// still inside the invoice directory before opening it.
        /// </summary>
        public string ReadInvoiceContained(string name)
        {
            var root = Path.GetFullPath(InvoiceRoot);
            var target = Path.GetFullPath(Path.Combine(root, name));
            if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                throw new UnauthorizedAccessException("path escapes the invoice directory");
            }
            return File.ReadAllText(target);
        }

        public byte[] Encrypt(byte[] data)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Key;
                aes.Mode = CipherMode.ECB;
                var enc = aes.CreateEncryptor();
                return enc.TransformFinalBlock(data, 0, data.Length);
            }
        }

        /// <summary>
        /// Authenticated encryption with a fresh nonce per message; the nonce
        /// and tag are prefixed so the reader can recover them.
        /// </summary>
        public byte[] Seal(byte[] data, byte[] key)
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var cipherText = new byte[data.Length];
            using (var gcm = new AesGcm(key))
            {
                gcm.Encrypt(nonce, data, cipherText, tag);
            }
            var output = new byte[nonce.Length + tag.Length + cipherText.Length];
            Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, output, nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherText, 0, output, nonce.Length + tag.Length, cipherText.Length);
            return output;
        }

        public string HashPassword(string pw)
        {
            using (var md5 = MD5.Create())
                return BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(pw)));
        }

        /// <summary>
        /// Password derivation for records written since the migration: random
        /// salt, a real iteration count, and both stored with the result.
        /// </summary>
        public string DerivePassword(string pw)
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            using (var kdf = new Rfc2898DeriveBytes(pw, salt, 600000, HashAlgorithmName.SHA256))
            {
                var dk = kdf.GetBytes(32);
                return "pbkdf2$600000$" + Convert.ToHexString(salt) + "$" + Convert.ToHexString(dk);
            }
        }

        public int WeakToken()
        {
            return new Random().Next();
        }

        /// <summary>Token drawn from the cryptographic generator.</summary>
        public string StrongToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        }

        public XmlDocument ParseFeed(string xml)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xml);
            return doc;
        }

        /// <summary>
        /// Feed parse with the resolver removed, so no external entity is ever
        /// fetched while the document is being read.
        /// </summary>
        public XmlDocument ParseFeedHardened(string xml)
        {
            var doc = new XmlDocument { XmlResolver = null };
            doc.LoadXml(xml);
            return doc;
        }

        public string Reflect(string body)
        {
            return "<div>" + body + "</div>";
        }

        /// <summary>Same fragment with the body encoded before it is embedded.</summary>
        public string ReflectEncoded(string body)
        {
            return "<div>" + HttpUtility.HtmlEncode(body) + "</div>";
        }

        /// <summary>Types the plugin loader is willing to construct.</summary>
        private static readonly Dictionary<string, Type> KnownTypes = new Dictionary<string, Type>
        {
            { "ledger", typeof(Ledger) },
            { "settlement", typeof(Settlement) },
        };

        public object CreateByName(string typeName)
        {
            var t = Type.GetType(typeName);
            return Activator.CreateInstance(t);
        }

        /// <summary>
        /// Construction narrowed to the registry above: the caller names a key
        /// this class defined, never a type it resolves at runtime.
        /// </summary>
        public object CreateKnown(string shortName)
        {
            if (!KnownTypes.TryGetValue(shortName, out var type))
            {
                throw new ArgumentException("unknown type: " + shortName);
            }
            return Activator.CreateInstance(type);
        }
    }
}
