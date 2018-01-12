using System;
using System.Data.SqlTypes;

// For the SQL Server integration
using Microsoft.SqlServer.Server;

// Other things we need for WebRequest
using System.Text;
using System.Security.Cryptography;

namespace hmac
{
    public partial class Functions
    {

        string _baseuri = "https://vip.bitcoin.co.id/tapi/";
        string _api_key;
        string _secret_key;

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString HashToString(SqlString message, SqlString keyStr)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyStr.ToString());

            byte[] b = new HMACSHA512(key).ComputeHash(Encoding.UTF8.GetBytes(message.ToString()));
            return Convert.ToBase64String(b);
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static string CreateSign(SqlString secret, SqlString source)

        {
            string ret = "";

            //private readonly Encoding encoding = Encoding.UTF8;
            var keyByte = Encoding.UTF8.GetBytes(secret.ToString());

            using (var hmacsha512 = new HMACSHA512(keyByte))
            {
                hmacsha512.ComputeHash(Encoding.UTF8.GetBytes(source.ToString()));
                ret = ByteToString(hmacsha512.Hash).ToLower();
            }

            return ret;
        }

        private static string ByteToString(byte[] buff)
        {
            string sbinary = "";
            for (int i = 0; i < buff.Length; i++)
                sbinary += buff[i].ToString("X2");
            return sbinary;
        }
    }
}
