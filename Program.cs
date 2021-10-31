using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace JWTing
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = "Book-Key";

            string jwt = GenerateJWT(key);
            System.Console.WriteLine(jwt);

            System.Console.WriteLine(VerifyJWT(jwt, key));
        }

        private static string GenerateJWT(string key)
        {
            using (HMAC mac = HMAC.Create("HMACSHA256"))
            {
                mac.Key = Encoding.UTF8.GetBytes(key);

                var hdr = new { alg = "HS256", typ = "JWT" };
                var payload = new { sub = "bookworm", role = "admin", aud = "BookClub" };

                string hdrJson = Encode(hdr);
                string payldJson = Encode(payload);

                byte[] hash = mac.ComputeHash(Encoding.UTF8.GetBytes($"{hdrJson}.{payldJson}"));

                string hashEncoded = WebEncoders.Base64UrlEncode(hash);

                return $"{hdrJson}.{payldJson}.{hashEncoded}";
            }
        }

        private static bool VerifyJWT(string jwt, string key)
        {
            string[] jwtParts = jwt.Split('.', StringSplitOptions.RemoveEmptyEntries);

            using (HMAC mac = HMAC.Create("HMACSHA256"))
            {
                mac.Key = Encoding.UTF8.GetBytes(key);
                byte[] hash = mac.ComputeHash(Encoding.UTF8.GetBytes($"{jwtParts[0]}.{jwtParts[1]}"));
                string hashEncoded = WebEncoders.Base64UrlEncode(hash);

                return hashEncoded == jwtParts[2];
            }
        }

        private static string Encode(object value)
        {
            return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)));
        }
    }
}
