/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Specifies the HTTP response header for the bearer authentication scheme.
    /// </summary>
    public sealed class OpenIdConnectChallengeContext : BaseContext {
        /// <summary>
        /// Initializes a new <see cref="OpenIdConnectChallengeContext"/>
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="challenge">The www-authenticate header value.</param>
        internal OpenIdConnectChallengeContext(
            HttpContext context,
            string challenge)
            : base(context) {
            Challenge = challenge;
        }

        /// <summary>
        /// The www-authenticate header value.
        /// </summary>
        public string Challenge { get; }
    }
}
