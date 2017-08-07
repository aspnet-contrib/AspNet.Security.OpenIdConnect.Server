/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration used by
    /// the OpenID Connect server handler is in a consistent and valid state.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIdConnectServerInitializer : IPostConfigureOptions<OpenIdConnectServerOptions>
    {
        private readonly ISystemClock _clock;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly IHostingEnvironment _hostingEnvironment;
        private readonly HtmlEncoder _htmlEncoder;
        private readonly ILogger<OpenIdConnectServerHandler> _logger;
        private readonly AuthenticationOptions _options;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIdConnectServerInitializer"/> class.
        /// </summary>
        public OpenIdConnectServerInitializer(
            [NotNull] ISystemClock clock,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] IHostingEnvironment hostingEnvironment,
            [NotNull] HtmlEncoder htmlEncoder,
            [NotNull] ILogger<OpenIdConnectServerHandler> logger,
            [NotNull] IOptions<AuthenticationOptions> options)
        {
            _clock = clock;
            _dataProtectionProvider = dataProtectionProvider;
            _hostingEnvironment = hostingEnvironment;
            _htmlEncoder = htmlEncoder;
            _logger = logger;
            _options = options.Value;
        }

        /// <summary>
        /// Populates the default OpenID Connect server options and ensure
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([NotNull] string name, [NotNull] OpenIdConnectServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            if (options.Provider == null && options.ProviderType == null)
            {
                throw new InvalidOperationException("The authorization provider registered in the options cannot be null.");
            }

            if (options.ProviderType != null && !typeof(OpenIdConnectServerProvider).IsAssignableFrom(options.ProviderType))
            {
                throw new InvalidOperationException($"The authorization provider must derive from 'OpenIdConnectServerProvider'.");
            }

            if (options.Issuer != null)
            {
                if (!options.Issuer.IsAbsoluteUri)
                {
                    throw new InvalidOperationException("The issuer registered in the options must be a valid absolute URI.");
                }

                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!string.IsNullOrEmpty(options.Issuer.Query) || !string.IsNullOrEmpty(options.Issuer.Fragment))
                {
                    throw new InvalidOperationException("The issuer registered in the options must " +
                                                        "contain no query and no fragment parts.");
                }

                // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
                // in AspNet.Security.OpenIdConnect.Server would prevent the end developer from
                // running the different samples in test environments, where HTTPS is often disabled.
                // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!options.AllowInsecureHttp && string.Equals(options.Issuer.Scheme, "http", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("The issuer registered in the options must be a " +
                                                        "HTTPS URI when AllowInsecureHttp is not set to true.");
                }
            }

            // Ensure at least one signing certificate/key was registered if an access token handler was registered.
            if (options.AccessTokenHandler != null && options.SigningCredentials.Count == 0)
            {
                throw new InvalidOperationException(
                    "At least one signing key must be registered when using JWT as the access token format. " +
                    "Consider registering a X.509 certificate using 'options.SigningCredentials.AddCertificate()' " +
                    "or 'options.SigningCredentials.AddDevelopmentCertificate()' or call " +
                    "'options.SigningCredentials.AddEphemeralKey()' to use an ephemeral key.");
            }

            // Make sure that none of the default schemes points to the configured scheme.
            if (string.Equals(_options.DefaultScheme, name, StringComparison.Ordinal) ||
                string.Equals(_options.DefaultAuthenticateScheme, name, StringComparison.Ordinal) ||
                string.Equals(_options.DefaultChallengeScheme, name, StringComparison.Ordinal) ||
                string.Equals(_options.DefaultForbidScheme, name, StringComparison.Ordinal) ||
                string.Equals(_options.DefaultSignInScheme, name, StringComparison.Ordinal) ||
                string.Equals(_options.DefaultSignOutScheme, name, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The OpenID Connect server handler cannot be used as the default scheme handler. " +
                    "Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, " +
                    "DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme" +
                    "point to an instance of the OpenID Connect server handler.");
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = _dataProtectionProvider;
            }

            if (options.AccessTokenFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerHandler),
                    nameof(options.AccessTokenFormat), name);

                options.AccessTokenFormat = new TicketDataFormat(protector);
            }

            if (options.AuthorizationCodeFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerHandler),
                    nameof(options.AuthorizationCodeFormat), name);

                options.AuthorizationCodeFormat = new TicketDataFormat(protector);
            }

            if (options.RefreshTokenFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerHandler),
                    nameof(options.RefreshTokenFormat), name);

                options.RefreshTokenFormat = new TicketDataFormat(protector);
            }

            if (options.HtmlEncoder == null)
            {
                options.HtmlEncoder = _htmlEncoder;
            }

            if (options.SystemClock == null)
            {
                options.SystemClock = _clock;
            }

            if (options.AllowInsecureHttp && _hostingEnvironment.IsProduction())
            {
                _logger.LogWarning("Disabling the transport security requirement is not recommended in production. " +
                                   "Consider setting 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'false' " +
                                   "to prevent the OpenID Connect server middleware from serving non-HTTPS requests.");
            }
        }
    }
}
