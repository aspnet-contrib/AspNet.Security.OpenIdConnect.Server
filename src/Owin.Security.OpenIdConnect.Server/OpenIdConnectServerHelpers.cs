/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OpenIdConnect.Server
{
    internal static class OpenIdConnectServerHelpers
    {
        public static RSA GenerateRsaKey(int size)
        {
            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var rsa = RSA.Create();

            if (rsa.KeySize < size)
            {
                rsa.KeySize = size;
            }

            if (rsa.KeySize < size && rsa is RSACryptoServiceProvider)
            {
                rsa.Dispose();
#if SUPPORTS_CNG
                rsa = new RSACng(size);
#else
                rsa = new RSACryptoServiceProvider(size);
#endif
            }

            if (rsa.KeySize < size)
            {
                throw new InvalidOperationException("The RSA key generation failed.");
            }

            return rsa;
        }

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

        public static string GetKeyIdentifier(this SecurityKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key is X509SecurityKey x509SecurityKey)
            {
                return x509SecurityKey.Certificate.Thumbprint;
            }

            if (key is RsaSecurityKey rsaSecurityKey)
            {
                // Note: if the RSA parameters are not attached to the signing key,
                // extract them by calling ExportParameters on the RSA instance.
                var parameters = rsaSecurityKey.Parameters;
                if (parameters.Modulus == null)
                {
                    parameters = rsaSecurityKey.Rsa.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Modulus != null,
                        "A null modulus shouldn't be returned by RSA.ExportParameters().");
                }

                // Only use the 40 first chars of the base64url-encoded modulus.
                var identifier = Base64UrlEncoder.Encode(parameters.Modulus);
                return identifier.Substring(0, Math.Min(identifier.Length, 40)).ToUpperInvariant();
            }

#if SUPPORTS_ECDSA
            if (key is ECDsaSecurityKey ecsdaSecurityKey)
            {
                // Extract the ECDSA parameters from the signing credentials.
                var parameters = ecsdaSecurityKey.ECDsa.ExportParameters(includePrivateParameters: false);

                Debug.Assert(parameters.Q.X != null,
                    "Invalid coordinates shouldn't be returned by ECDsa.ExportParameters().");

                // Only use the 40 first chars of the base64url-encoded X coordinate.
                var identifier = Base64UrlEncoder.Encode(parameters.Q.X);
                return identifier.Substring(0, Math.Min(identifier.Length, 40)).ToUpperInvariant();
            }
#endif

            return null;
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

        public static bool IsSupportedAlgorithm(this SecurityKey key, string algorithm)
        {
            return key.CryptoProviderFactory.IsSupportedAlgorithm(algorithm, key);
        }

        public static HashAlgorithm GetHashAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.HmacSha256:
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.EcdsaSha256Signature:
                    return SHA256.Create();

                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.HmacSha384:
                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.EcdsaSha384Signature:
                    return SHA384.Create();

                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.HmacSha512:
                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.EcdsaSha512Signature:
                    return SHA512.Create();
            }

            throw new NotSupportedException($"The hash algorithm cannot be inferred from the '{algorithm}' signature algorithm.");
        }

        public static string GetJwtAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                    return SecurityAlgorithms.EcdsaSha256;

                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                    return SecurityAlgorithms.EcdsaSha384;

                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha512Signature:
                    return SecurityAlgorithms.EcdsaSha512;

                case SecurityAlgorithms.HmacSha256:
                case SecurityAlgorithms.HmacSha256Signature:
                    return SecurityAlgorithms.HmacSha256;

                case SecurityAlgorithms.HmacSha384:
                case SecurityAlgorithms.HmacSha384Signature:
                    return SecurityAlgorithms.HmacSha384;

                case SecurityAlgorithms.HmacSha512:
                case SecurityAlgorithms.HmacSha512Signature:
                    return SecurityAlgorithms.HmacSha512;

                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return SecurityAlgorithms.RsaSha256;

                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return SecurityAlgorithms.RsaSha384;

                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha512Signature:
                    return SecurityAlgorithms.RsaSha512;

                case SecurityAlgorithms.RsaOaepKeyWrap:
                    return "RSA-OAEP";

                case SecurityAlgorithms.RsaV15KeyWrap:
                    return "RSA1_5";

                default:
                    return null;
            }
        }

#if SUPPORTS_ECDSA
        public static string GetJwtAlgorithmCurve(ECCurve curve)
        {
            if (curve.IsNamed)
            {
                if (curve.Oid.FriendlyName == ECCurve.NamedCurves.nistP256.Oid.FriendlyName)
                {
                    return JsonWebKeyECTypes.P256;
                }

                else if (curve.Oid.FriendlyName == ECCurve.NamedCurves.nistP384.Oid.FriendlyName)
                {
                    return JsonWebKeyECTypes.P384;
                }

                else if (curve.Oid.FriendlyName == ECCurve.NamedCurves.nistP521.Oid.FriendlyName)
                {
                    return JsonWebKeyECTypes.P521;
                }
            }

            return null;
        }
#endif

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

                case JsonClaimValueTypes.Json:
                case JsonClaimValueTypes.JsonArray:
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
