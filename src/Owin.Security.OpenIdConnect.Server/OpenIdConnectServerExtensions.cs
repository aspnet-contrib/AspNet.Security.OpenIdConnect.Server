/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Owin.Security.OpenIdConnect.Server;

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
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current request from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current request.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest(this IOwinContext context) {
            return context.GetOpenIdConnectMessage(OpenIdConnectConstants.Environment.Request);
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> request in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectRequest(this IOwinContext context, OpenIdConnectMessage request) {
            context.SetOpenIdConnectMessage(OpenIdConnectConstants.Environment.Request, request);
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current response from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current response.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectResponse(this IOwinContext context) {
            return context.GetOpenIdConnectMessage(OpenIdConnectConstants.Environment.Response);
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> response in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectResponse(this IOwinContext context, OpenIdConnectMessage response) {
            context.SetOpenIdConnectMessage(OpenIdConnectConstants.Environment.Response, response);
        }

        private static OpenIdConnectMessage GetOpenIdConnectMessage(this IOwinContext context, string key) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            if (string.IsNullOrWhiteSpace(key)) {
                throw new ArgumentException("key");
            }

            var message = context.Get<OpenIdConnectMessage>(key + OpenIdConnectConstants.Environment.Message);
            if (message != null) {
                return message;
            }

            var parameters = context.Get<IReadOnlyDictionary<string, string[]>>(key + OpenIdConnectConstants.Environment.Parameters);
            if (parameters != null) {
                return new OpenIdConnectMessage(parameters);
            }

            return null;
        }

        private static void SetOpenIdConnectMessage(this IOwinContext context, string key, OpenIdConnectMessage message) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            if (string.IsNullOrWhiteSpace(key)) {
                throw new ArgumentException("key");
            }

            if (message == null) {
                context.Environment.Remove(key + OpenIdConnectConstants.Environment.Message);
                context.Environment.Remove(key + OpenIdConnectConstants.Environment.Parameters);

                return;
            }

            var parameters = new ReadOnlyDictionary<string, string[]>(
                message.Parameters.ToDictionary(
                    keySelector: parameter => parameter.Key,
                    elementSelector: parameter => new[] { parameter.Value }));

            context.Set(key + OpenIdConnectConstants.Environment.Message, message);
            context.Set(key + OpenIdConnectConstants.Environment.Parameters, parameters);
        }
    }
}
