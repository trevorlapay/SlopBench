using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.Web;

namespace SlopShop.Payments
{
    public class PaymentsController
    {
        private const string ConnStr =
            "Server=db.internal;Database=payments;User Id=sa;Password=Sup3rS3cret!;";

        private static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789abcdef");
        private static readonly byte[] IV = Encoding.UTF8.GetBytes("abcdef0123456789");

        public object GetPayment(string userId)
        {
            using (var conn = new SqlConnection(ConnStr))
            {
                conn.Open();
                var cmd = new SqlCommand("SELECT * FROM payments WHERE user_id = '" + userId + "'", conn);
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

        public string XPathLookup(string user)
        {
            var doc = new XPathDocument("users.xml");
            var nav = doc.CreateNavigator();
            return nav.SelectSingleNode("//user[name='" + user + "']/token").Value;
        }

        public void RunReport(string arg)
        {
            Process.Start("cmd.exe", "/c report.exe " + arg);
        }

        public string ReadInvoice(string name)
        {
            return File.ReadAllText(Path.Combine(@"C:\invoices", name));
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

        public string HashPassword(string pw)
        {
            using (var md5 = MD5.Create())
                return BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(pw)));
        }

        public int WeakToken()
        {
            return new Random().Next();
        }

        public XmlDocument ParseFeed(string xml)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xml);
            return doc;
        }

        public string Reflect(string body)
        {
            return "<div>" + body + "</div>";
        }

        public object CreateByName(string typeName)
        {
            var t = Type.GetType(typeName);
            return Activator.CreateInstance(t);
        }
    }
}
