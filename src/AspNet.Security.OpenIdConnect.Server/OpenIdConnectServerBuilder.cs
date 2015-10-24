/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.ComponentModel;
using AspNet.Security.OpenIdConnect.Server;

namespace Microsoft.AspNet.Builder {
    /// <summary>
    /// Holds various properties allowing to configure the OpenID Connect server middleware.
    /// </summary>
    public class OpenIdConnectServerBuilder {
        public OpenIdConnectServerBuilder(IApplicationBuilder builder) {
            Builder = builder;
        }

        /// <summary>
        /// Gets the ASP.NET application builder used by this instance.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IApplicationBuilder Builder { get; }

        /// <summary>
        /// Gets the options used by the OpenID Connect server middleware.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; set; } = new OpenIdConnectServerOptions();

        /// <summary>
        /// Sets the <see cref="OpenIdConnectServerProvider"/> used to control the authorization process.
        /// Implementing <see cref="OpenIdConnectServerProvider.ValidateClientRedirectUri"/> and
        /// <see cref="OpenIdConnectServerProvider.ValidateClientAuthentication"/> is recommended.
        /// </summary>
        public OpenIdConnectServerProvider Provider {
            set { Options.Provider = value; }
        }

        /// <summary>
        /// Gets the properties dictionary associated with this instance.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IDictionary<string, object> Properties { get; } = new Dictionary<string, object>();
    }
}
