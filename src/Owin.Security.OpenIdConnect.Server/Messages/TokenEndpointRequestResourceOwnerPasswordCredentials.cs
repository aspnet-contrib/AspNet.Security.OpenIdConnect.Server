/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Owin.Security.OpenIdConnect.Server.Messages {
    /// <summary>
    /// Data object used by TokenEndpointRequest when the "grant_type" is "password".
    /// </summary>    
    public class TokenEndpointRequestResourceOwnerPasswordCredentials {
        /// <summary>
        /// The value passed to the Token endpoint in the "username" parameter
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "password" parameter
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "scope" parameter
        /// </summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "This is just a data class.")]
        public IList<string> Scope { get; set; }
    }
}
