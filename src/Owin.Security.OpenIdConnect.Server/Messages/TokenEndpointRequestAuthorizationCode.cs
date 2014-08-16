/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;

namespace Owin.Security.OpenIdConnect.Server.Messages {
    /// <summary>
    /// Data object used by TokenEndpointRequest when the "grant_type" is "authorization_code".
    /// </summary>    
    public class TokenEndpointRequestAuthorizationCode {
        /// <summary>
        /// The value passed to the Token endpoint in the "code" parameter
        /// </summary>
        public string Code { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "redirect_uri" parameter. This MUST be provided by the caller
        /// if the original visit to the Authorize endpoint contained a "redirect_uri" parameter.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings", Justification = "By design")]
        public string RedirectUri { get; set; }
    }
}
