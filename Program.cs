using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Linq.Expressions;
using System.Xml.Linq;

namespace Sample
{
    class Program
    {

        public const string UserName = "";             //place the webservice account username provided by the team here.
        ///public const string UserPassword = "[******]";     //place the webservice account password provided by the team here.      
        public const string Domain = "[portal].csod.com";     //place the portal name provided by the team here.
        public const string ApiKey = ""; //place the webservice ApiKey provided by the team here.
        public const string apiSecret = "";//place the webservice apiSecret provided by the team here.


        static void Main(string[] args)
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls11
                                        | System.Net.SecurityProtocolType.Tls12;
            FetchSecretTokenAndCallService();
        }

        private static void FetchSecretTokenAndCallService()
        {
            string Alias = UserName + Guid.NewGuid().ToString().Replace("-", "");   
           
            var uri = new Uri(string.Format(@"https://"+ Domain + "/services/api/sts/Session?userName={0}&alias={1}", UserName, Alias));

            var request = WebRequest.Create(uri);
            request.Method = "POST";

            //create request Header
            request.Headers.Add("x-csod-api-key", ApiKey);
            request.Headers.Add("x-csod-date", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.000"));
            Console.WriteLine(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.000"));
           
            request.ContentType = "text/xml";

            var stringToSign = ConstructStringToSign(request.Method, request.Headers, uri.AbsolutePath);
            var sig = SignString512(stringToSign, apiSecret);
            request.Headers.Add("x-csod-signature", sig);
            request.Timeout = 999999;
            request.ContentLength = 0;

            var headers = request.Headers.ToString();

            // If you want it formated in some other way.
            Console.WriteLine(headers);
           
            string token = "";
            string secret = "";
            using (var response = request.GetResponse())
            {
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    string responseFromServer = reader.ReadToEnd();
                    Console.WriteLine(responseFromServer);                    
                   var xdoc= XDocument.Parse(responseFromServer);                  

                    var result = from e in xdoc.Root.Descendants().Where(n => n.Name.LocalName == "data")
                                 .Descendants().Where(n => n.Name.LocalName == "Session")  //.Where(n => n.Name.LocalName == "Token")
                                 select new
                                 {
                                     sessionToken = e.Elements().Where(f => f.Name.LocalName == "Token").FirstOrDefault().Value,
                                     Secret = e.Elements().Where(f => f.Name.LocalName == "Secret").FirstOrDefault().Value
                                 };
                    token = result.Select(x => x.sessionToken).FirstOrDefault();
                    secret = result.Select(x => x.Secret).FirstOrDefault();                  
                  
                }
            }

            ServiceCall(token, secret);
        }

        public static  string ServiceCall(string token, string secret)
        {
            var uri = new Uri(@"https://"+ Domain + "/services/api/x/users/v1/employees");
            var request = (HttpWebRequest)WebRequest.Create(uri);

            var sessionToken = token;
            var sessionTokenSecret = secret;

            request.Headers.Add("x-csod-date", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.000"));
            request.Headers.Add("x-csod-session-token", sessionToken);
            request.Method = "GET";

            var stringToSign = ConstructStringToSign(request.Method, request.Headers, uri.AbsolutePath);
            var sig = SignString512(stringToSign, sessionTokenSecret);
            request.Headers.Add("x-csod-signature", sig);
            
            request.ContentType = "application/json";
            request.Timeout = 999999;
            

            string responseFromServer = string.Empty;
            try
            {

                using (var response = request.GetResponse())
                {
                    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        responseFromServer = reader.ReadToEnd();
                    }
                }
            }
            catch (WebException wx)
            {
                StreamReader reader = new StreamReader(wx.Response.GetResponseStream());
                string error = reader.ReadToEnd();
            }

            return responseFromServer;
        }

       

        //Method for creating header
        public static string ConstructStringToSign(string httpMethod, NameValueCollection headers, string pathAndQuery)
        {
            StringBuilder stringToSign = new StringBuilder();
            var httpVerb = httpMethod.Trim() + "\n";
            var csodHeaders = headers.Cast<string>().Where(w => w.StartsWith("x-csod-"))
                                                    .Where(w => w != "x-csod-signature")
                                                    .Distinct()
                                                    .OrderBy(s => s)
                                                    .Aggregate(string.Empty, (a, l) => a + l.ToLower().Trim() + ":" + headers[l].Trim() + "\n");
            stringToSign.Append(httpVerb);
            stringToSign.Append(csodHeaders);
            stringToSign.Append(pathAndQuery);
            return stringToSign.ToString();
        }

        //Method for encryption
        public static string SignString512(string stringToSign, string secretKey)
        {
            byte[] secretkeyBytes = Convert.FromBase64String(secretKey);
            byte[] inputBytes = Encoding.UTF8.GetBytes(stringToSign);
            using (var hmac = new HMACSHA512(secretkeyBytes))
            {
                byte[] hashValue = hmac.ComputeHash(inputBytes);
                return System.Convert.ToBase64String(hashValue);
            }
        }

    }
}
