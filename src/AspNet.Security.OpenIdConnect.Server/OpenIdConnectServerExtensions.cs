/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Framework.OptionsModel;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides extension methods allowing to easily register an
    /// ASP.NET-powered OpenID Connect server and to retrieve various
    /// OpenID Connect-related contexts from the ASP.NET environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Adds a specs-compliant OpenID Connect server in the ASP.NET pipeline.
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="options">Options which control the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder</returns>
        public static IApplicationBuilder UseOpenIdConnectServer(this IApplicationBuilder app, Action<OpenIdConnectServerOptions> options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<OpenIdConnectServerMiddleware>(new ConfigureOptions<OpenIdConnectServerOptions>(options));
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current request from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current request.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest(this HttpContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = GetFeature(context);

            return feature.Request;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> request in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectRequest(this HttpContext context, OpenIdConnectMessage request) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = GetFeature(context);

            feature.Request = request;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current response from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current response.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectResponse(this HttpContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = GetFeature(context);

            return feature.Response;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> response in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectResponse(this HttpContext context, OpenIdConnectMessage response) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = GetFeature(context);

            feature.Response = response;
        }

        private static IOpenIdConnectServerFeature GetFeature(HttpContext context) {
            var feature = context.GetFeature<IOpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.SetFeature(feature);
            }

            return feature;
        }

        internal static bool IsSupportedAlgorithm(this SecurityKey securityKey, string algorithm) {
            var x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey == null) {
                return false;
            }

            var rsaPrivateKey = x509SecurityKey.PrivateKey as RSACryptoServiceProvider;
            if (rsaPrivateKey == null) {
                return false;
            }

            return true;
        }
    }
}
