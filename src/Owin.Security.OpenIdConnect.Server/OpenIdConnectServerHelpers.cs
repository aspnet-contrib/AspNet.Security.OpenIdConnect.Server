using System;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server
{
    internal static class OpenIdConnectServerHelpers
    {

        public static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, string thumbprint)
        {
            var store = new X509Store(name, location);

            try
            {
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                return certificates.OfType<X509Certificate2>().SingleOrDefault();
            }

            finally
            {
                store.Close();
            }
        }

        public static SecurityKeyIdentifier GetKeyIdentifier(this SecurityKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            SecurityKeyIdentifier identifier = null;
            X509Certificate2 certificate = null;

            var x509SecurityKey = key as X509SecurityKey;
            if (x509SecurityKey != null)
            {
                certificate = x509SecurityKey.Certificate;
            }

            var x509AsymmetricSecurityKey = key as X509AsymmetricSecurityKey;
            if (x509AsymmetricSecurityKey != null)
            {
                // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                // Reflection is the only way to get the certificate used to create the security key.
                var field = typeof(X509AsymmetricSecurityKey).GetField(
                    name: "certificate",
                    bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);
                Debug.Assert(field != null, "The 'certificate' field shouldn't be missing.");

                certificate = (X509Certificate2) field.GetValue(x509AsymmetricSecurityKey);
            }

            if (certificate != null)
            {
                identifier = new SecurityKeyIdentifier {
                    new X509IssuerSerialKeyIdentifierClause(x509SecurityKey.Certificate),
                    new X509RawDataKeyIdentifierClause(x509SecurityKey.Certificate),
                    new X509ThumbprintKeyIdentifierClause(x509SecurityKey.Certificate),
                    new LocalIdKeyIdentifierClause(x509SecurityKey.Certificate.Thumbprint.ToUpperInvariant()),
                    new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5t, x509SecurityKey.Certificate.Thumbprint.ToUpperInvariant())
                };
            }

            if (identifier == null)
            {
                // Create an empty security key identifier.
                identifier = new SecurityKeyIdentifier();

                var rsaSecurityKey = key as RsaSecurityKey;
                if (rsaSecurityKey != null)
                {
                    // Resolve the underlying algorithm from the security key.
                    var algorithm = (RSA) rsaSecurityKey.GetAsymmetricAlgorithm(
                        algorithm: SecurityAlgorithms.RsaSha256Signature,
                        requiresPrivateKey: false);

                    Debug.Assert(algorithm != null,
                        "SecurityKey.GetAsymmetricAlgorithm() shouldn't return a null algorithm.");

                    // Export the RSA public key to extract a key identifier based on the modulus component.
                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Modulus != null,
                        "RSA.ExportParameters() shouldn't return a null modulus.");

                    // Only use the 40 first chars of the base64url-encoded modulus.
                    var kid = Base64UrlEncoder.Encode(parameters.Modulus);
                    kid = kid.Substring(0, Math.Min(kid.Length, 40)).ToUpperInvariant();

                    identifier.Add(new RsaKeyIdentifierClause(algorithm));
                    identifier.Add(new LocalIdKeyIdentifierClause(kid));
                    identifier.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.Kid, kid));
                }
            }

            // Mark the security key identifier as read-only to
            // ensure it can't be altered during a request.
            identifier.MakeReadOnly();

            return identifier;
        }

        public static string GetIssuer(this IOwinContext context, OpenIdConnectServerOptions options)
        {
            var issuer = options.Issuer;
            if (issuer == null)
            {
                if (!Uri.TryCreate(context.Request.Scheme + "://" + context.Request.Host +
                                   context.Request.PathBase, UriKind.Absolute, out issuer))
                {
                    throw new InvalidOperationException("The issuer address cannot be inferred from the current request");
                }
            }

            return issuer.AbsoluteUri;
        }

        public static string AddPath(this string address, PathString path)
        {
            if (address.EndsWith("/"))
            {
                address = address.Substring(0, address.Length - 1);
            }

            return address + path;
        }

        public static bool IsEquivalentTo(this PathString path, PathString other)
        {
            if (path.Equals(other))
            {
                return true;
            }

            if (path.Equals(other + new PathString("/")))
            {
                return true;
            }

            if (other.Equals(path + new PathString("/")))
            {
                return true;
            }

            return false;
        }

        public static string GetJwtAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            switch (algorithm)
            {
                case OpenIdConnectConstants.Algorithms.HmacSha256:
                case SecurityAlgorithms.HmacSha256Signature:
                    return JwtAlgorithms.HMAC_SHA256;

                case OpenIdConnectConstants.Algorithms.HmacSha384:
                case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384":
                    return JwtAlgorithms.HMAC_SHA384;

                case OpenIdConnectConstants.Algorithms.HmacSha512:
                case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512":
                    return JwtAlgorithms.HMAC_SHA512;

                case OpenIdConnectConstants.Algorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return JwtAlgorithms.RSA_SHA256;

                case OpenIdConnectConstants.Algorithms.RsaSha384:
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
                    return JwtAlgorithms.RSA_SHA384;

                case OpenIdConnectConstants.Algorithms.RsaSha512:
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                    return JwtAlgorithms.RSA_SHA512;

                case SecurityAlgorithms.RsaOaepKeyWrap:
                    return "RSA-OAEP";

                case SecurityAlgorithms.RsaV15KeyWrap:
                    return "RSA1_5";

                default:
                    return null;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool AreEqual(string first, string second)
        {
            // Note: these null checks can be theoretically considered as early checks
            // (which would defeat the purpose of a time-constant comparison method),
            // but the expected string length is the only information an attacker
            // could get at this stage, which is not critical where this method is used.

            if (first == null && second == null)
            {
                return true;
            }

            if (first == null || second == null)
            {
                return false;
            }

            if (first.Length != second.Length)
            {
                return false;
            }

            var result = true;

            for (var index = 0; index < first.Length; index++)
            {
                result &= first[index] == second[index];
            }

            return result;
        }
    }
}
