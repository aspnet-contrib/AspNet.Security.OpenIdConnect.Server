using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    internal static class OpenIdConnectServerHelpers {
        internal static RSA GenerateKey(int size) {
            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var algorithm = RSA.Create();

            if (algorithm.KeySize < size) {
                algorithm.KeySize = size;
            }

            // Note: RSACng cannot be used as it's not available on Mono.
            if (algorithm.KeySize < size) {
                algorithm.Dispose();
                algorithm = new RSACryptoServiceProvider(size);
            }

            if (algorithm.KeySize < size) {
                throw new InvalidOperationException("The dynamic RSA key generation failed.");
            }

            return algorithm;
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

        internal static IDictionary<string, byte[]> GetKeys(DirectoryInfo directory) {
            var keys = new Dictionary<string, byte[]>();
            
            foreach (var file in directory.EnumerateFiles("*.key")) {
                try {
                    using (var buffer = new MemoryStream())
                    using (var stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read)) {
                        // Copy the key content to the buffer.
                        stream.CopyTo(buffer);

                        // Add the key to the returned dictionary.
                        keys.Add(file.FullName, buffer.ToArray());
                    }
                }

                catch { }
            }

            return keys;
        }

        internal static string PersistKey(DirectoryInfo directory, byte[] key) {
            // Generate a new file name for the key and determine its absolute path.
            var path = Path.Combine(directory.FullName, Guid.NewGuid().ToString() + ".key");

            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                // Write the encrypted key to the file stream.
                stream.Write(key, 0, key.Length);
            }

            return path;
        }

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

        internal static DirectoryInfo GetDefaultKeyStorageDirectory() {
            string path;

            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID"))) {
                path = Environment.GetEnvironmentVariable("HOME");
                if (!string.IsNullOrEmpty(path)) {
                    try {
                        return GetKeyStorageDirectoryFromBasePath(path);
                    }

                    catch { }
                }
            }

            // Note: Environment.GetFolderPath may return null if the user profile is not loaded.
            path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            if (!string.IsNullOrEmpty(path)) {
                try {
                    return GetKeyStorageDirectoryFromBasePath(path);
                }

                catch { }
            }

            // On Linux environments, use the HOME variable.
            path = Environment.GetEnvironmentVariable("HOME");
            if (!string.IsNullOrEmpty(path)) {
                try {
                    return Directory.CreateDirectory(Path.Combine(path, ".aspnet", "aspnet-contrib", "oidc-server"));
                }

                catch { }
            }

            // Use the ASPNET_TEMP environment variable when specified.
            path = Environment.GetEnvironmentVariable("ASPNET_TEMP");
            if (!string.IsNullOrEmpty(path)) {
                try {
                    return GetKeyStorageDirectoryFromBasePath(path);
                }

                catch { }
            }

            // Note: returning the TEMP directory is safe as keys are always encrypted using the
            // data protection system, making the keys unreadable outside this environment.
            path = Path.GetTempPath();
            if (!string.IsNullOrEmpty(path)) {
                try {
                    return GetKeyStorageDirectoryFromBasePath(path);
                }

                catch { }
            }

            return null;
        }

        private static DirectoryInfo GetKeyStorageDirectoryFromBasePath(string path) {
            return Directory.CreateDirectory(Path.Combine(path, "ASP.NET", "aspnet-contrib", "oidc-server"));
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
