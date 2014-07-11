// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Specifies the HTTP response header for the bearer authentication scheme.
    /// </summary>
    public class OpenIdConnectChallengeContext : BaseContext {
        /// <summary>
        /// Initializes a new <see cref="OpenIdConnectRequestTokenContext"/>
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="challenge">The www-authenticate header value.</param>
        public OpenIdConnectChallengeContext(
            IOwinContext context,
            string challenge)
            : base(context) {
            Challenge = challenge;
        }

        /// <summary>
        /// The www-authenticate header value.
        /// </summary>
        public string Challenge { get; protected set; }
    }
}
