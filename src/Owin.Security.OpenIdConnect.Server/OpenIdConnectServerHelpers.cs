/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

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

            if (key is X509SecurityKey x509SecurityKey)
            {
                certificate = x509SecurityKey.Certificate;
            }

            if (key is X509AsymmetricSecurityKey x509AsymmetricSecurityKey)
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
                identifier = new SecurityKeyIdentifier
                {
                    new X509IssuerSerialKeyIdentifierClause(certificate),
                    new X509RawDataKeyIdentifierClause(certificate),
                    new X509ThumbprintKeyIdentifierClause(certificate),
                    new LocalIdKeyIdentifierClause(certificate.Thumbprint.ToUpperInvariant()),
                    new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5t, certificate.Thumbprint.ToUpperInvariant())
                };
            }

            if (identifier == null)
            {
                // Create an empty security key identifier.
                identifier = new SecurityKeyIdentifier();

                if (key is RsaSecurityKey rsaSecurityKey)
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

        public static OpenIdConnectParameter AsParameter(this Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            switch (claim.ValueType)
            {
                case ClaimValueTypes.Boolean:
                {
                    if (bool.TryParse(claim.Value, out bool value))
                    {
                        return value;
                    }

                    goto default;
                }

                case ClaimValueTypes.Integer:
                case ClaimValueTypes.Integer32:
                case ClaimValueTypes.Integer64:
                {
                    if (long.TryParse(claim.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long value))
                    {
                        return value;
                    }

                    goto default;
                }

                case JwtConstants.JsonClaimValueType:
                {
                    try
                    {
                        return JToken.Parse(claim.Value);
                    }

                    // Swallow the conversion exceptions and serialize
                    // the claim value as a string when an error occurs.
                    catch (Exception exception) when (exception is ArgumentException ||
                                                      exception is FormatException ||
                                                      exception is InvalidCastException ||
                                                      exception is JsonReaderException ||
                                                      exception is JsonSerializationException)
                    {
                        goto default;
                    }
                }

                default: return new OpenIdConnectParameter(claim.Value);
            }
        }

        public static KeyValuePair<string, string>? GetClientCredentials(this IHeaderDictionary headers)
        {
            if (headers == null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            string header = headers["Authorization"];
            if (string.IsNullOrEmpty(header))
            {
                return null;
            }

            if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            string UnescapeDataString(string value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    return null;
                }

                return Uri.UnescapeDataString(value.Replace("+", "%20"));
            }

            try
            {
                var value = header.Substring("Basic ".Length).Trim();
                var data = Encoding.ASCII.GetString(Convert.FromBase64String(value));

                var index = data.IndexOf(':');
                if (index < 0)
                {
                    return null;
                }

                return new KeyValuePair<string, string>(
                    /* client_id: */ UnescapeDataString(data.Substring(0, index)),
                    /* client_secret: */ UnescapeDataString(data.Substring(index + 1)));
            }

            catch
            {
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

        public class Appender
        {
            private readonly char _delimiter;
            private readonly StringBuilder _sb;
            private bool _hasDelimiter;

            public Appender(string value, char delimiter)
            {
                _sb = new StringBuilder(value);
                _delimiter = delimiter;
                _hasDelimiter = value.IndexOf(delimiter) != -1;
            }

            public Appender Append(string name, string value)
            {
                _sb.Append(_hasDelimiter ? '&' : _delimiter)
                   .Append(Uri.EscapeDataString(name))
                   .Append('=')
                   .Append(Uri.EscapeDataString(value));
                _hasDelimiter = true;
                return this;
            }

            public override string ToString()
            {
                return _sb.ToString();
            }
        }
    }
}
