using System.Security.Cryptography;
using System.Text;

namespace HelloWorld
{
    class Program
    {
        private static string secret = "";// uth token from twilio console
        private static HMACSHA1 _hmac;
        private static SHA256 _sha;
        private static string _computedHashWithPort = "";
        private static string _computedHashWithoutPort = "";
        static void Main(string[] args)
        {
            _hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secret));
            _sha = SHA256.Create();

            var parameters = new Dictionary<string, string>
            {
                {"AccountSid", "AC7142004b3f01eb514e5d561c6d19277f"},
                {"CompositionSid", "CJc3afd1df53458d1d2ebbe7332b3adfea"},
                {"CompositionUri", "/v1/Compositions/CJc3afd1df53458d1d2ebbe7332b3adfea"},
                {"Duration", "4"},
                {"MediaUri", "/v1/Compositions/CJc3afd1df53458d1d2ebbe7332b3adfea"},
                {"RoomSid", "RMcef505a5a944e10e65796d316f801608"},
                {"Size", "54872"},
                {"StatusCallbackEvent", "composition-available"},
                {"Timestamp", "2022-08-29T13:05:13.0672"}
            };

            const string twilioSignature = "eNEcmB2q+Y9xF1ff1AsG3y7oY8w=";

            const  string url = "https://ltrttpx.rpdy.io/api/twilio/composition-events";

            bool result = Validate(url, parameters, twilioSignature);

            Console.Clear();
            Console.WriteLine("Validator Result: "+ result.ToString());
            System.Console.WriteLine("twilioSignature: " + twilioSignature);
            System.Console.WriteLine("Computed Hash With Port: " + _computedHashWithPort);
            System.Console.WriteLine("Computed Hash Without Port: " + _computedHashWithoutPort);
        }

         /// <summary>
        /// Validate against a request
        /// </summary>
        /// <param name="url">Request URL</param>
        /// <param name="parameters">Request parameters</param>
        /// <param name="expected">Expected result</param>
        /// <returns>true if the signature matches the result; false otherwise</returns>
        public static bool Validate(string url, IDictionary<string, string> parameters, string expected)
        {
            // check signature of url with and without port, since sig generation on back end is inconsistent
            var signatureWithoutPort = GetValidationSignature(RemovePort(url), parameters);
            var signatureWithPort = GetValidationSignature(AddPort(url), parameters);

            _computedHashWithPort = signatureWithPort;
            _computedHashWithoutPort = signatureWithoutPort;

            // If either url produces a valid signature, we accept the request as valid
            return SecureCompare(signatureWithoutPort, expected) || SecureCompare(signatureWithPort, expected);
        }

        private static string GetValidationSignature(string url, IDictionary<string, string> parameters)
        {
            var b = new StringBuilder(url);
            if (parameters != null)
            {
                var sortedKeys = new List<string>(parameters.Keys);
                sortedKeys.Sort(StringComparer.Ordinal);

                foreach (var key in sortedKeys)
                {
                    b.Append(key).Append(parameters[key] ?? "");
                }
            }

            var hash = _hmac.ComputeHash(Encoding.UTF8.GetBytes(b.ToString()));
            return Convert.ToBase64String(hash);
        }

        private static bool SecureCompare(string a, string b)
        {
            if (a == null || b == null)
            {
                return false;
            }

            var n = a.Length;
            if (n != b.Length)
            {
                return false;
            }

            var mismatch = 0;
            for (var i = 0; i < n; i++)
            {
                mismatch |= a[i] ^ b[i];
            }

            return mismatch == 0;
        }

        private static string RemovePort(string url)
        {
            return SetPort(url, -1);
        }

        private static string AddPort(string url)
        {
            var uri = new UriBuilder(url);
            return SetPort(url, uri.Port);
        }

        private static string SetPort(string url, int port)
        {
            var uri = new UriBuilder(url);
            uri.Host = PreserveCase(url, uri.Host);
            if (port == -1)
            {
                uri.Port = port;
            }
            else if ((port != 443) && (port != 80))
            {
                uri.Port = port;
            }
            else
            {
                uri.Port = uri.Scheme == "https" ? 443 : 80;
            }
            var scheme = PreserveCase(url, uri.Scheme);
            return uri.Uri.OriginalString.Replace(uri.Scheme, scheme);
        }

        private static string PreserveCase(string url, string replacementString)
        {
            var startIndex = url.IndexOf(replacementString, StringComparison.OrdinalIgnoreCase);
            return url.Substring(startIndex, replacementString.Length);
        }
    }
}