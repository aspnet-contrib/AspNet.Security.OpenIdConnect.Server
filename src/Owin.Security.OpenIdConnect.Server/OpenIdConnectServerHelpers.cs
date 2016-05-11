using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    internal static class OpenIdConnectServerHelpers {
        internal static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, string thumbprint) {
            var store = new X509Store(name, location);

            try {
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                return certificates.OfType<X509Certificate2>().SingleOrDefault();
            }

            finally {
                store.Close();
            }
        }

        internal static string GetIssuer(this IOwinContext context, OpenIdConnectServerOptions options) {
            var issuer = options.Issuer;
            if (issuer == null) {
                if (!Uri.TryCreate(context.Request.Scheme + "://" + context.Request.Host +
                                   context.Request.PathBase, UriKind.Absolute, out issuer)) {
                    throw new InvalidOperationException("The issuer address cannot be inferred from the current request");
                }
            }

            return issuer.AbsoluteUri;
        }

        internal static string AddPath(this string address, PathString path) {
            if (address.EndsWith("/")) {
                address = address.Substring(0, address.Length - 1);
            }

            return address + path;
        }

        internal static string GetJwtAlgorithm(string algorithm) {
            if (string.IsNullOrEmpty(algorithm)) {
                throw new ArgumentNullException(nameof(algorithm));
            }

            switch (algorithm) {
                case SecurityAlgorithms.HmacSha256Signature:
                    return JwtAlgorithms.HMAC_SHA256;

                case SecurityAlgorithms.RsaSha256Signature:
                    return JwtAlgorithms.RSA_SHA256;

                case SecurityAlgorithms.RsaOaepKeyWrap:
                    return "RSA-OAEP";

                case SecurityAlgorithms.RsaV15KeyWrap:
                    return "RSA1_5";

                default:
                    throw new InvalidOperationException($"The '{algorithm}' has no corresponding JWA identifier.");
            }
        }

        internal static string GenerateKey(this RandomNumberGenerator generator, int length) {
            if (generator == null) {
                throw new ArgumentNullException(nameof(generator));
            }

            var bytes = new byte[length];
            generator.GetBytes(bytes);

            return Base64UrlEncoder.Encode(bytes);
        }
    }
}
