/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server.Messages {
    /// <summary>
    /// Data object used by TokenEndpointRequest which contains parameter information when the "grant_type" is unrecognized.
    /// </summary>
    public class TokenEndpointRequestCustomExtension {
        /// <summary>
        /// The parameter information when the "grant_type" is unrecognized.
        /// </summary>
        public IReadableStringCollection Parameters { get; set; }
    }
}
