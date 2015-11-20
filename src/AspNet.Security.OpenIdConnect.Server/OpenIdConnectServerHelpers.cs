using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.PlatformAbstractions;
using Microsoft.Extensions.Primitives;

namespace AspNet.Security.OpenIdConnect.Server {
    internal static class OpenIdConnectServerHelpers {
        internal static RSA GenerateKey(IRuntimeEnvironment environment) {
            if (string.Equals(environment.OperatingSystem, "Windows", StringComparison.OrdinalIgnoreCase)) {
#if DNXCORE50
                // On CoreCLR, use RSACng.
                return new RSACng(2048);
#else
                // On desktop CLR, use RSACryptoServiceProvider.
                return new RSACryptoServiceProvider(2048);
#endif
            }

            // When the runtime is identified as Mono, use RSACryptoServiceProvider, independently of the operating system.
            if (string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase)) {
                return new RSACryptoServiceProvider(2048);
            }

#if DNXCORE50
            // On Linux and Darwin, use RSAOpenSsl when running on CoreCLR.
            if (string.Equals(environment.OperatingSystem, "Linux", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(environment.OperatingSystem, "Darwin", StringComparison.OrdinalIgnoreCase)) {
                return new RSAOpenSsl(2048);
            }
#endif

            // If no appropriate implementation can be found, throw an exception.
            throw new PlatformNotSupportedException("No RSA implementation compatible with your configuration can be found.");
        }

        internal static byte[] EncryptKey(IDataProtector protector, RSAParameters parameters, string usage) {
            if (protector == null) {
                throw new ArgumentNullException(nameof(protector));
            }

            if (string.IsNullOrEmpty(usage)) {
                throw new ArgumentNullException(nameof(usage));
            }

            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(/* version: */ 2);
                writer.Write(/* algorithm: */ "RSA");
                writer.Write(/* usage: */ usage);

                // Serialize the RSA parameters to the key file.
                writer.Write(parameters.D.Length);
                writer.Write(parameters.D);
                writer.Write(parameters.DP.Length);
                writer.Write(parameters.DP);
                writer.Write(parameters.DQ.Length);
                writer.Write(parameters.DQ);
                writer.Write(parameters.Exponent.Length);
                writer.Write(parameters.Exponent);
                writer.Write(parameters.InverseQ.Length);
                writer.Write(parameters.InverseQ);
                writer.Write(parameters.Modulus.Length);
                writer.Write(parameters.Modulus);
                writer.Write(parameters.P.Length);
                writer.Write(parameters.P);
                writer.Write(parameters.Q.Length);
                writer.Write(parameters.Q);

                // Encrypt the key using the data protection block.
                return protector.Protect(stream.ToArray());
            }
        }

        internal static RSAParameters? DecryptKey(IDataProtector protector, byte[] buffer, out string usage) {
            if (protector == null) {
                throw new ArgumentNullException(nameof(protector));
            }

            if (buffer == null) {
                throw new ArgumentNullException(nameof(buffer));
            }

            usage = null;

            // Note: an exception thrown in this block may be caused by a corrupted or inappropriate key
            // (for instance, if the key was created for another application or another environment).
            // Always catch the exception and return null in this case to avoid leaking sensitive data.
            try {
                var bytes = protector.Unprotect(buffer);
                if (bytes == null) {
                    return null;
                }

                using (var stream = new MemoryStream(bytes))
                using (var reader = new BinaryReader(stream)) {
                    if (/* version: */ reader.ReadInt32() != 2) {
                        return null;
                    }

                    // Note: only RSA keys are currently supported. Return null if another format has been used.
                    if (!string.Equals(/* algorithm: */ reader.ReadString(), "RSA", StringComparison.OrdinalIgnoreCase)) {
                        return null;
                    }

                    // Read the usage from the serialized key.
                    usage = reader.ReadString();

                    // Extract the RSA parameters from the serialized key.
                    return new RSAParameters {
                        D = reader.ReadBytes(reader.ReadInt32()),
                        DP = reader.ReadBytes(reader.ReadInt32()),
                        DQ = reader.ReadBytes(reader.ReadInt32()),
                        Exponent = reader.ReadBytes(reader.ReadInt32()),
                        InverseQ = reader.ReadBytes(reader.ReadInt32()),
                        Modulus = reader.ReadBytes(reader.ReadInt32()),
                        P = reader.ReadBytes(reader.ReadInt32()),
                        Q = reader.ReadBytes(reader.ReadInt32())
                    };
                }
            }

            catch {
                return null;
            }
        }

        internal static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, string thumbprint) {
            var store = new X509Store(name, location);

            try {
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                return certificates.OfType<X509Certificate2>().SingleOrDefault();
            }

            finally {
#if DNXCORE50
                store.Dispose();
#else
                store.Close();
#endif
            }
        }

        internal static DirectoryInfo GetDefaultKeyStorageDirectory() {
            string path;

            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID"))) {
                path = Environment.GetEnvironmentVariable("HOME");
                if (!string.IsNullOrEmpty(path)) {
                    return GetKeyStorageDirectoryFromBaseAppDataPath(path);
                }
            }

#if !DNXCORE50
            // Note: Environment.GetFolderPath may return null if the user profile is not loaded.
            path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            if (!string.IsNullOrEmpty(path)) {
                return GetKeyStorageDirectoryFromBaseAppDataPath(path);
            }

            // Returning the current directory is safe as keys are always encrypted using the
            // data protection system, making the keys unreadable outside this environment.
            return new DirectoryInfo(Directory.GetCurrentDirectory());
#else

            // Try to resolve the AppData/Local folder
            // using the LOCALAPPDATA environment variable.
            path = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (!string.IsNullOrEmpty(path)) {
                return GetKeyStorageDirectoryFromBaseAppDataPath(path);
            }

            // If the LOCALAPPDATA environment variable was not found,
            // try to determine the actual AppData/Local path from USERPROFILE.
            path = Environment.GetEnvironmentVariable("USERPROFILE");
            if (!string.IsNullOrEmpty(path)) {
                return GetKeyStorageDirectoryFromBaseAppDataPath(Path.Combine(path, "AppData", "Local"));
            }

            // On Linux environments, use the HOME variable.
            path = Environment.GetEnvironmentVariable("HOME");
            if (!string.IsNullOrEmpty(path)) {
                return new DirectoryInfo(Path.Combine(path, ".aspnet", "aspnet-contrib", "aspnet-oidc-server"));
            }
            
            // Returning the current directory is safe as keys are always encrypted using the
            // data protection system, making the keys unreadable outside this environment.
            return new DirectoryInfo(Directory.GetCurrentDirectory());
#endif
        }

        private static DirectoryInfo GetKeyStorageDirectoryFromBaseAppDataPath(string path) {
            return new DirectoryInfo(Path.Combine(path, "ASP.NET", "aspnet-contrib", "aspnet-oidc-server"));
        }

        internal static string GetIssuer([NotNull] this HttpContext context, [NotNull] OpenIdConnectServerOptions options) {
            var issuer = options.Issuer;
            if (issuer == null) {
                if (!Uri.TryCreate(context.Request.Scheme + "://" + context.Request.Host +
                                   context.Request.PathBase, UriKind.Absolute, out issuer)) {
                    throw new InvalidOperationException("The issuer address cannot be inferred from the current request");
                }
            }

            return issuer.AbsoluteUri;
        }

        internal static string AddPath([NotNull] this string address, PathString path) {
            if (address.EndsWith("/")) {
                address = address.Substring(0, address.Length - 1);
            }

            return address + path;
        }

        internal static IEnumerable<KeyValuePair<string, string[]>> ToDictionary(this IEnumerable<KeyValuePair<string, StringValues>> collection) {
            return collection.Select(item => new KeyValuePair<string, string[]>(item.Key, item.Value.ToArray()));
        }

        internal static Task SetAsync(
            [NotNull] this IDistributedCache cache, [NotNull] string key,
            [NotNull] Func<DistributedCacheEntryOptions, byte[]> factory) {
            var options = new DistributedCacheEntryOptions();
            var buffer = factory(options);

            return cache.SetAsync(key, buffer, options);
        }

        internal static bool IsSupportedAlgorithm([NotNull] this SecurityKey key, [NotNull] string algorithm) {
            // Note: SecurityKey currently doesn't support IsSupportedAlgorithm.
            // To work around this limitation, this static extension tries to
            // determine whether the given security key supports the specified
            // algorithm via CryptoConfig when available or using a pre-defined table.
            var symmetricSecurityKey = key as SymmetricSecurityKey;
            if (symmetricSecurityKey != null) {
#if DNX451
                if (CryptoConfig.CreateFromName(algorithm) is SymmetricAlgorithm) {
                    return true;
                }
#endif
                switch (algorithm) {
                    case SecurityAlgorithms.HmacSha256Signature:
                    case SecurityAlgorithms.HMAC_SHA256:
                    case SecurityAlgorithms.HMAC_SHA384:
                    case SecurityAlgorithms.HMAC_SHA512:
                        return true;

                    case SecurityAlgorithms.Aes128Encryption:
                    case SecurityAlgorithms.Aes128KeyWrap:
                        return symmetricSecurityKey.KeySize >= 128 &&
                               symmetricSecurityKey.KeySize <= 256;

                    case SecurityAlgorithms.Aes192Encryption:
                    case SecurityAlgorithms.Aes192KeyWrap:
                        return symmetricSecurityKey.KeySize >= 192 &&
                               symmetricSecurityKey.KeySize <= 256;

                    case SecurityAlgorithms.Aes256Encryption:
                    case SecurityAlgorithms.Aes256KeyWrap:
                        return symmetricSecurityKey.KeySize == 256;

                    default:
                        return false;
                }
            }

            else if (key is AsymmetricSecurityKey) {
#if DNX451
                if (CryptoConfig.CreateFromName(algorithm) is AsymmetricAlgorithm) {
                    return true;
                }
#endif

                switch (algorithm) {
                    case SecurityAlgorithms.RsaSha256Signature:
                    case SecurityAlgorithms.RsaSha384Signature:
                    case SecurityAlgorithms.RsaSha512Signature:
                    case SecurityAlgorithms.RSA_SHA256:
                    case SecurityAlgorithms.RSA_SHA384:
                    case SecurityAlgorithms.RSA_SHA512:
                    case SecurityAlgorithms.RsaOaepKeyWrap:
                    case SecurityAlgorithms.RsaV15KeyWrap: {
                        if (key is RsaSecurityKey) {
                            return true;
                        }

                        var x509SecurityKey = key as X509SecurityKey;
                        if (x509SecurityKey != null) {
#if DNX451
                            return x509SecurityKey.Certificate.PublicKey.Key is RSA;
#else
                            return x509SecurityKey.Certificate.GetRSAPublicKey() != null;
#endif
                        }

                        return false;
                    }

#if DNXCORE50
                    // Note: the ECDsa type exists on .NET 4.5.1 but not on Mono 4.3.
                    // To prevent this code path from throwing an exception
                    // on Mono, the following algorithms are ignored on DNX451.
                    case SecurityAlgorithms.ECDSA_SHA256:
                    case SecurityAlgorithms.ECDSA_SHA384:
                    case SecurityAlgorithms.ECDSA_SHA512: {
                        if (key is ECDsaSecurityKey) {
                            return true;
                        }

                        var x509SecurityKey = key as X509SecurityKey;
                        if (x509SecurityKey != null) {
                            return x509SecurityKey.Certificate.GetECDsaPublicKey() != null;
                        }

                        return false;
                    }
#endif

                    default:
                        return false;
                }
            }

            // If the security key doesn't inherit from SymmetricSecurityKey
            // or AsymmetricSecurityKey, it must be treated as an invalid key
            // and false must be returned to indicate that it cannot be used
            // with the specified algorithm.
            return false;
        }

        internal static string GetJwtAlgorithm(string algorithm) {
            if (string.IsNullOrEmpty(algorithm)) {
                throw new ArgumentNullException(nameof(algorithm));
            }

            switch (algorithm) {
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.HMAC_SHA256:
                    return JwtAlgorithms.HMAC_SHA256;

                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RSA_SHA256:
                    return JwtAlgorithms.RSA_SHA256;

                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RSA_SHA384:
                    return JwtAlgorithms.RSA_SHA384;

                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.RSA_SHA512:
                    return JwtAlgorithms.RSA_SHA512;

                case SecurityAlgorithms.RsaOaepKeyWrap:
                    return "RSA-OAEP";

                case SecurityAlgorithms.RsaV15KeyWrap:
                    return "RSA1_5";

                default:
                    throw new InvalidOperationException($"The '{algorithm}' has no corresponding JWA identifier.");
            }
        }

        internal static bool ContainsSet(this IEnumerable<string> source, IEnumerable<string> set) {
            if (source == null || set == null) {
                return false;
            }

            return new HashSet<string>(source).IsSupersetOf(set);
        }
    }
}
