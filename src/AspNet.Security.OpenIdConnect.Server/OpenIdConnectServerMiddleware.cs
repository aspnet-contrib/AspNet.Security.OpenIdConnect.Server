/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Authorization Server middleware component which is added to an OWIN pipeline. This class is not
    /// created by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer
    /// extension method.
    /// </summary>
    public class OpenIdConnectServerMiddleware : AuthenticationMiddleware<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Authorization Server middleware component which is added to an OWIN pipeline. This constructor is not
        /// called by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer
        /// extension method.
        /// </summary>
        public OpenIdConnectServerMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<OpenIdConnectServerOptions> options,
            [NotNull] IHostingEnvironment environment,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] HtmlEncoder htmlEncoder,
            [NotNull] UrlEncoder urlEncoder,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, urlEncoder)
        {
            if (Options.Provider == null)
            {
                throw new ArgumentException("The authorization provider registered in the options cannot be null.", nameof(options));
            }

            if (Options.SystemClock == null)
            {
                throw new ArgumentException("The system clock registered in the options cannot be null.", nameof(options));
            }

            if (Options.Issuer != null)
            {
                if (!Options.Issuer.IsAbsoluteUri)
                {
                    throw new ArgumentException("The issuer registered in the options must be a valid absolute URI.", nameof(options));
                }

                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!string.IsNullOrEmpty(Options.Issuer.Query) || !string.IsNullOrEmpty(Options.Issuer.Fragment))
                {
                    throw new ArgumentException("The issuer registered in the options must contain " +
                                                "no query and no fragment parts.", nameof(options));
                }

                // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
                // in AspNet.Security.OpenIdConnect.Server would prevent the end developer from
                // running the different samples in test environments, where HTTPS is often disabled.
                // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!Options.AllowInsecureHttp && string.Equals(Options.Issuer.Scheme, "http", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException("The issuer registered in the options must be a HTTPS URI when " +
                                                "AllowInsecureHttp is not set to true.", nameof(options));
                }
            }

            if (Options.AutomaticAuthenticate || Options.AutomaticChallenge)
            {
                throw new ArgumentException("Automatic authentication cannot be used with " +
                                            "the OpenID Connect server middleware.", nameof(options));
            }

            if (Options.AccessTokenHandler != null && !(Options.AccessTokenHandler is JwtSecurityTokenHandler))
            {
                throw new ArgumentException("The access token handler must be derived from 'JwtSecurityTokenHandler'.", nameof(options));
            }

            // Ensure at least one signing certificate/key was registered if an access token handler was registered.
            if (Options.AccessTokenHandler != null && Options.SigningCredentials.Count == 0)
            {
                throw new ArgumentException("At least one signing key must be registered when using JWT as the access token format. " +
                                            "Consider registering a X.509 certificate using 'services.AddOpenIddict().AddSigningCertificate()' " +
                                            "or call 'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.", nameof(options));
            }

            if (Options.DataProtectionProvider == null)
            {
                Options.DataProtectionProvider = dataProtectionProvider;
            }

            if (Options.AccessTokenFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationScheme, "Access_Token", "v1");

                Options.AccessTokenFormat = new TicketDataFormat(protector);
            }

            if (Options.AuthorizationCodeFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationScheme, "Authentication_Code", "v1");

                Options.AuthorizationCodeFormat = new TicketDataFormat(protector);
            }

            if (Options.RefreshTokenFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationScheme, "Refresh_Token", "v1");

                Options.RefreshTokenFormat = new TicketDataFormat(protector);
            }

            if (Options.HtmlEncoder == null)
            {
                Options.HtmlEncoder = htmlEncoder;
            }

            if (Options.AllowInsecureHttp && environment.IsProduction())
            {
                Logger.LogWarning("Disabling the transport security requirement is not recommended in production. " +
                                  "Consider setting 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'false' " +
                                  "to prevent the OpenID Connect server middleware from serving non-HTTPS requests.");
            }
        }

        /// <summary>
        /// Called by the AuthenticationMiddleware base class to create a per-request handler.
        /// </summary>
        /// <returns>A new instance of the request handler</returns>
        protected override AuthenticationHandler<OpenIdConnectServerOptions> CreateHandler()
        {
            return new OpenIdConnectServerHandler();
        }
    }
}
