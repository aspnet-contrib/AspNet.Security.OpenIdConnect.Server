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
    /// OWIN-powered OpenID connect server and to retrieve various
    /// OpenID connect-related contexts from the OWIN environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Adds a specs-compliant OpenID connect server in the OWIN pipeline.
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="options">Options which control the behavior of the OpenID connect server.</param>
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
        /// Retrieves the <see cref="AuthorizeEndpointRequest"/> instance
        /// associated with the current request from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="AuthorizeEndpointRequest"/> associated with the current request.</returns>
        public static AuthorizeEndpointRequest GetAuthorizeEndpointRequest(this IOwinContext context) {
            const string key = OpenIdConnectConstants.Environment.AuthorizeEndpointRequest;

            if (context == null) {
                throw new ArgumentNullException("context");
            }

            var request = context.Get<IEnumerable<KeyValuePair<string, string[]>>>(key);
            if (request == null) {
                return null;
            }

            return new AuthorizeEndpointRequest(request.AsReadableStringCollection());
        }

        /// <summary>
        /// Inserts the ambient <see cref="AuthorizeEndpointRequest"/> in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="request">The ambient <see cref="AuthorizeEndpointRequest"/>.</param>
        /// <returns>The <see cref="AuthorizeEndpointRequest"/> associated with the current request.</returns>
        internal static void SetAuthorizeEndpointRequest(this IOwinContext context, AuthorizeEndpointRequest request) {
            const string key = OpenIdConnectConstants.Environment.AuthorizeEndpointRequest;

            if (context == null) {
                throw new ArgumentNullException("context");
            }

            if (request == null) {
                throw new ArgumentNullException("request");
            }

            context.Set<IEnumerable<KeyValuePair<string, string[]>>>(key, request.Parameters);
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
