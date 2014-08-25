/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin;
using Owin.Security.OpenIdConnect.Server;
using Owin.Security.OpenIdConnect.Server.Messages;

namespace Owin {
    /// <summary>
    /// Provides extension methods allowing to easily register an
    /// OWIN-powered OpenID Connect server and to retrieve various
    /// OpenID Connect-related contexts from the OWIN environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Adds a specs-compliant OpenID Connect server in the OWIN pipeline.
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="options">Options which control the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder</returns>
        public static IAppBuilder UseOpenIdConnectServer(this IAppBuilder app, OpenIdConnectServerOptions options) {
            if (app == null) {
                throw new ArgumentNullException("app");
            }

            if (options == null) {
                throw new ArgumentNullException("options");
            }

            return app.Use(typeof(OpenIdConnectServerMiddleware), app, options);
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectAuthorizationRequest"/> instance
        /// associated with the current request from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="OpenIdConnectAuthorizationRequest"/> associated with the current request.</returns>
        public static OpenIdConnectAuthorizationRequest GetAuthorizationRequest(this IOwinContext context) {
            const string key = OpenIdConnectConstants.Environment.AuthorizationRequest;

            if (context == null) {
                throw new ArgumentNullException("context");
            }

            var request = context.Get<IEnumerable<KeyValuePair<string, string[]>>>(key);
            if (request == null) {
                return null;
            }

            return new OpenIdConnectAuthorizationRequest(request.AsReadableStringCollection());
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectAuthorizationRequest"/> in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectAuthorizationRequest"/>.</param>
        internal static void SetAuthorizationRequest(this IOwinContext context, OpenIdConnectAuthorizationRequest request) {
            const string key = OpenIdConnectConstants.Environment.AuthorizationRequest;

            if (context == null) {
                throw new ArgumentNullException("context");
            }

            if (request == null) {
                throw new ArgumentNullException("request");
            }

            context.Set<IEnumerable<KeyValuePair<string, string[]>>>(key, request.Parameters);
        }

        /// <summary>
        /// Retrieves the oauth.Error value associated with the current request from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="errorDescription">The oauth.ErrorDescription associated with the current request.</param>
        /// <param name="errorUri">The oauth.ErrorUri associated with the current request.</param>
        /// <returns>The oauth.Error associated with the current request.</returns>
        public static string GetAuthorizationRequestError(this IOwinContext context, out string errorDescription, out string errorUri) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            errorDescription = context.Get<string>(OpenIdConnectConstants.Environment.ErrorDescription);
            errorUri = context.Get<string>(OpenIdConnectConstants.Environment.ErrorUri);

            return context.Get<string>(OpenIdConnectConstants.Environment.Error);
        }

        /// <summary>
        /// Determines whether the OWIN context contains an oauth.Error value associated with the current request.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="error">The oauth.Error associated with the current request.</param>
        /// <param name="errorDescription">The oauth.ErrorDescription associated with the current request.</param>
        /// <param name="errorUri">The oauth.ErrorUri associated with the current request.</param>
        /// <returns>Returns true if the context contains a non-null oauth.Error value.</returns>
        public static bool TryGetAuthorizationRequestError(this IOwinContext context, out string error, out string errorDescription, out string errorUri) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            error = context.Get<string>(OpenIdConnectConstants.Environment.Error);
            errorDescription = context.Get<string>(OpenIdConnectConstants.Environment.ErrorDescription);
            errorUri = context.Get<string>(OpenIdConnectConstants.Environment.ErrorUri);

            return !string.IsNullOrWhiteSpace(error);
        }

        /// <summary>
        /// Inserts the ambient oauth.Error in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="error">The ambient oauth.Error.</param>
        /// <param name="errorDescription">The ambient oauth.ErrorDescription.</param>
        /// <param name="errorUri">The ambient oauth.ErrorDescription.</param>
        public static void SetAuthorizationRequestError(this IOwinContext context, string error, string errorDescription = null, string errorUri = null) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            if (string.IsNullOrWhiteSpace(error)) {
                throw new ArgumentException("error");
            }

            context.Set(OpenIdConnectConstants.Environment.Error, error);

            if (!string.IsNullOrWhiteSpace(errorDescription)) {
                context.Set(OpenIdConnectConstants.Environment.ErrorDescription, errorDescription);
            }

            if (!string.IsNullOrWhiteSpace(errorUri)) {
                context.Set(OpenIdConnectConstants.Environment.ErrorUri, errorUri);
            }
        }

        /// <summary>
        /// Converts an enumeration to an <see cref="IReadableStringCollection"/> instance.
        /// </summary>
        /// <param name="enumeration">The enumeration to convert.</param>
        /// <returns>The resulting <see cref="IReadableStringCollection"/> instance.</returns>
        private static IReadableStringCollection AsReadableStringCollection(this IEnumerable<KeyValuePair<string, string[]>> enumeration) {
            if (enumeration == null) {
                throw new ArgumentNullException("enumeration");
            }

            var collection = enumeration as IReadableStringCollection;
            if (collection != null) {
                return collection;
            }

            return new ReadableStringCollection(enumeration.ToDictionary(kvp => kvp.Key, kvp => kvp.Value));
        }
    }
}
