/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.DataProtection;
using Microsoft.Framework.Caching.Distributed;
using Microsoft.Framework.Internal;
using Microsoft.Framework.Logging;
using Microsoft.Framework.WebEncoders;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Authorization Server middleware component which is added to an OWIN pipeline. This class is not
    /// created by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
    /// extension method.
    /// </summary>
    public class OpenIdConnectServerMiddleware : AuthenticationMiddleware<OpenIdConnectServerOptions> {
        /// <summary>
        /// Authorization Server middleware component which is added to an OWIN pipeline. This constructor is not
        /// called by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
        /// extension method.
        /// </summary>
        public OpenIdConnectServerMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] OpenIdConnectServerOptions options,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] IDistributedCache cache,
            [NotNull] IHtmlEncoder htmlEncoder,
            [NotNull] IUrlEncoder urlEncoder,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, urlEncoder) {
            if (string.IsNullOrEmpty(Options.AuthenticationScheme)) {
                throw new ArgumentNullException(nameof(Options.AuthenticationScheme));
            }

            if (Options.RandomNumberGenerator == null) {
                throw new ArgumentNullException(nameof(Options.RandomNumberGenerator));
            }

            if (Options.Provider == null) {
                throw new ArgumentNullException(nameof(Options.Provider));
            }

            if (Options.SystemClock == null) {
                throw new ArgumentNullException(nameof(Options.SystemClock));
            }

            if (Options.Issuer != null) {
                if (!Options.Issuer.IsAbsoluteUri) {
                    throw new ArgumentException("options.Issuer must be a valid absolute URI.", "options.Issuer");
                }

                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!string.IsNullOrEmpty(Options.Issuer.Query) || !string.IsNullOrEmpty(Options.Issuer.Fragment)) {
                    throw new ArgumentException("options.Issuer must contain no query and no fragment parts.", "options.Issuer");
                }

                // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
                // in Owin.Security.OpenIdConnect.Server would prevent the end developer from
                // running the different samples in test environments, where HTTPS is often disabled.
                // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!Options.AllowInsecureHttp && string.Equals(Options.Issuer.Scheme, "http", StringComparison.OrdinalIgnoreCase)) {
                    throw new ArgumentException("options.Issuer must be a HTTPS URI when " +
                        "options.AllowInsecureHttp is not set to true.", "options.Issuer");
                }
            }

            if (Options.AuthorizationCodeFormat == null) {
                Options.AuthorizationCodeFormat = dataProtectionProvider.CreateTicketFormat(
                    typeof(OpenIdConnectServerMiddleware).FullName,
                    Options.AuthenticationScheme, "Authentication_Code", "v1");
            }

            if (Options.AccessTokenFormat == null) {
                Options.AccessTokenFormat = dataProtectionProvider.CreateTicketFormat(
                    typeof(OpenIdConnectServerMiddleware).FullName,
                    Options.AuthenticationScheme, "Access_Token", "v1");
            }

            if (Options.RefreshTokenFormat == null) {
                Options.RefreshTokenFormat = dataProtectionProvider.CreateTicketFormat(
                    typeof(OpenIdConnectServerMiddleware).Namespace,
                    Options.AuthenticationScheme, "Refresh_Token", "v1");
            }

            if (Options.Cache == null) {
                Options.Cache = cache;
            }

            if (Options.HtmlEncoder == null) {
                Options.HtmlEncoder = htmlEncoder;
            }

            // If no key has been explicitly added, use the fallback mode.
            if (Options.SigningCredentials.Count == 0) {
                var directory = GetDefaultKeyStorageDirectory();

                // Ensure the directory exists.
                if (!directory.Exists) {
                    directory.Create();
                    directory.Refresh();
                }

                // Create a new app-specific data protector.
                var protector = dataProtectionProvider.CreateProtector(
                    typeof(OpenIdConnectServerMiddleware).Namespace,
                    Options.AuthenticationScheme, "Signing_Credentials", "v1");

                Options.UseKeys(directory, protector);

                // If no signing key has been found,
                // generate and persist a new RSA key.
                if (Options.SigningCredentials.Count == 0) {
                    // Generate a new 2048 bit RSA key and export its public/private parameters.
                    var provider = new RSACryptoServiceProvider(2048);
                    var parameters = provider.ExportParameters(includePrivateParameters: true);

                    // Generate a new file name for the key and determine its absolute path.
                    var path = Path.Combine(directory.FullName, Guid.NewGuid().ToString() + ".key");

                    using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                        // Encrypt the key using the data protector.
                        var bytes = protector.EncryptKey(parameters);

                        // Write the encrypted key to the file stream.
                        stream.Write(bytes, 0, bytes.Length);
                    }

                    Options.UseKey(new RsaSecurityKey(parameters));
                }
            }
        }

        /// <summary>
        /// Called by the AuthenticationMiddleware base class to create a per-request handler. 
        /// </summary>
        /// <returns>A new instance of the request handler</returns>
        protected override AuthenticationHandler<OpenIdConnectServerOptions> CreateHandler() {
            return new OpenIdConnectServerHandler();
        }

        private static DirectoryInfo GetDefaultKeyStorageDirectory() {
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
    }
}
