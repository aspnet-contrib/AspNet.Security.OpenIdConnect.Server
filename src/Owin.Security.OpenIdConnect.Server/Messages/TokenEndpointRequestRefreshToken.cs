/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Owin.Security.OpenIdConnect.Server.Messages {
    /// <summary>
    /// Data object used by TokenEndpointRequest when the "grant_type" parameter is "refresh_token".
    /// </summary>
    public class TokenEndpointRequestRefreshToken {
        /// <summary>
        /// The value passed to the Token endpoint in the "refresh_token" parameter
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "scope" parameter
        /// </summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "This is just a data container object.")]
        public IList<string> Scope { get; set; }
    }
}
