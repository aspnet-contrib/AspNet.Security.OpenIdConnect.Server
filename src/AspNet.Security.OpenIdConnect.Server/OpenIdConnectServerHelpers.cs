using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Primitives;

namespace AspNet.Security.OpenIdConnect.Server {
    internal static class OpenIdConnectServerHelpers {
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

        internal static bool IsSupportedAlgorithm([NotNull] this SecurityKey securityKey, [NotNull] string algorithm) {
            // Note: SecurityKey currently doesn't support IsSupportedAlgorithm.
            // To work around this limitation, this static extensions tries to
            // determine whether the security key supports RSA w/ SHA2 or not.
            if (!string.Equals(algorithm, SecurityAlgorithms.RsaSha256Signature, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(algorithm, SecurityAlgorithms.RsaSha384Signature, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(algorithm, SecurityAlgorithms.RsaSha512Signature, StringComparison.OrdinalIgnoreCase)) {
                return false;
            }

            var rsaSecurityKey = securityKey as RsaSecurityKey;
            if (rsaSecurityKey != null) {
                return rsaSecurityKey.HasPublicKey &&
                       rsaSecurityKey.HasPrivateKey;
            }

            var x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey == null || !x509SecurityKey.HasPublicKey) {
                return false;
            }

            var rsaPrivateKey = x509SecurityKey.PrivateKey as RSA;
            if (rsaPrivateKey == null) {
                return false;
            }

            return true;
        }

        internal static bool ContainsSet(this IEnumerable<string> source, IEnumerable<string> set) {
            if (source == null || set == null) {
                return false;
            }

            return new HashSet<string>(source).IsSupersetOf(set);
        }
    }
}
