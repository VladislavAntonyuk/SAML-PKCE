using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using RestSharp;

namespace SAML_PKCE
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("args:");
            foreach (var arg in args) Console.WriteLine(arg);

            var codeVerifier = "random_secret_string";
            if (args.Length == 0)
            {
                RegisterUrlScheme();
                var codeChallenge = ComputeSha256Hash(codeVerifier);
                Console.WriteLine("Enter IdP url");
                string idpUrl;
                do
                {
                    idpUrl = Console.ReadLine();
                } while (string.IsNullOrWhiteSpace(idpUrl));

                idpUrl += $"&code_challenge={codeChallenge}&client=desktop";
                Process.Start(idpUrl);
            }
            else
            {
                var arg1 = args[0];
                var authCode = arg1.Substring(arg1.IndexOf("authorizationCode") + "authorizationCode".Length + 1);
                Console.WriteLine("Enter host: https://site.me/");
                string host;
                do
                {
                    host = Console.ReadLine();
                } while (string.IsNullOrWhiteSpace(host));
                Console.WriteLine("Enter orgId. Leave blank for default");
                var orgId = Console.ReadLine() ?? "";
                var client = new RestClient($"{host}api/v1/token") { Timeout = -1 };
                var request = new RestRequest(Method.POST);
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddParameter("grant_type", "code");
                request.AddParameter("code", authCode);
                request.AddParameter("code_verifier", codeVerifier);
                request.AddParameter("orgid", orgId);
                var response = client.Execute(request);
                Console.WriteLine(response.Content);
                Console.ReadLine();
            }
        }

        private static string ComputeSha256Hash(string rawData)
        {
            using (var sha256Hash = SHA256.Create())
            {
                var bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                // Base64Url
                return Convert.ToBase64String(bytes).Split('=')[0].Replace('+', '-').Replace('/', '_');
            }
        }

        private static void RegisterUrlScheme()
        {
            if (Registry.ClassesRoot.OpenSubKey("moveit") != null) return;

            var key = Registry.ClassesRoot.CreateSubKey("moveit");
            key.SetValue("", "URL: MOVEIt Protocol");
            key.SetValue("URL Protocol", "");

            key = key.CreateSubKey("shell");
            key = key.CreateSubKey("open");
            key = key.CreateSubKey("command");

            var executionPath = Path.Combine(Environment.CurrentDirectory,
                $"{Assembly.GetEntryAssembly()?.GetName().Name}.exe");
            var commandValue = $"\"{executionPath}\" \"%1\"";
            key.SetValue("", commandValue);
        }
    }
}