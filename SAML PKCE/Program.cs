using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using RestSharp;

namespace SAML_PKCE
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("args:");
            foreach (var arg in args)
            {
                Console.WriteLine(arg);
            }

            string codeVerifier = "random_secret_string";
            if (args.Length == 0)
            {
                RegisterUrlScheme();
                var codeChallenge = ComputeSha256Hash(codeVerifier);
                Console.WriteLine("Enter IdP url");
                var idpUrl = Console.ReadLine();
                idpUrl += $"&code_challenge={codeChallenge}&client=desktop";
                Process.Start(idpUrl);
            }
            else
            {
                var arg1 = args[0];
                var authCode = arg1.Substring(arg1.IndexOf("authorizationCode") + "authorizationCode".Length + 1);
                Console.WriteLine("Enter host: https://moveit.myddns.me/");
                var host = Console.ReadLine();
                var client = new RestClient($"{host}api/v1/token") { Timeout = -1 };
                var request = new RestRequest(Method.POST);
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddParameter("grant_type", "saml");
                request.AddParameter("code", authCode);
                request.AddParameter("code_verifier", codeVerifier);
                var response = client.Execute(request);
                Console.WriteLine(response.Content);
                Console.ReadLine();
            }
        }

        static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private static void RegisterUrlScheme()
        {
            if (Registry.ClassesRoot.OpenSubKey("moveit") != null)
            {
                return;
            }

            var key = Registry.ClassesRoot.CreateSubKey("moveit");
            key.SetValue("", "URL: MOVEIt Protocol");
            key.SetValue("URL Protocol", "");

            key = key.CreateSubKey("shell");
            key = key.CreateSubKey("open");
            key = key.CreateSubKey("command");

            var executionPath = Path.Combine(Environment.CurrentDirectory, $"{ Assembly.GetEntryAssembly()?.GetName().Name}.exe");
            var commandValue = $"\"{executionPath}\" \"%1\"";
            key.SetValue("", commandValue);
        }
    }
}
