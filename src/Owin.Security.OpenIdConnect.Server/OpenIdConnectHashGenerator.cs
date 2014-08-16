/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Cryptography;
using System.Text;

namespace Owin.Security.OpenIdConnect.Server {
    public class OpenIdConnectHashGenerator {
        private static char base64PadCharacter = '=';
        private static char base64Character62 = '+';
        private static char base64Character63 = '/';
        private static char base64UrlCharacter62 = '-';
        private static char base64UrlCharacter63 = '_';

        public string GenerateHash(string code, string algorithm = null) {
            string hashString;
            using (var hashAlgorithm = HashAlgorithm.Create(algorithm)) {
                byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(code));
                hashString = Convert.ToBase64String(hashBytes, 0, hashBytes.Length / 2);
                hashString = hashString.Split(base64PadCharacter)[0]; // Remove any trailing padding
                hashString = hashString.Replace(base64Character62, base64UrlCharacter62); // 62nd char of encoding
                hashString = hashString.Replace(base64Character63, base64UrlCharacter63); // 63rd char of encoding
            }
            return hashString;
        }
    }
}
