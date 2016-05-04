/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security.Notifications;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server starts
    /// writing the revocation response to the response stream.
    /// </summary>
    public class ApplyRevocationResponseContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public ApplyRevocationResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            JObject response)
            : base(context, options) {
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the revocation request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the JSON payload returned to the caller.
        /// </summary>
        public new JObject Response { get; }

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <c>null</c>.
        /// </summary>
        public string Error => Response[OpenIdConnectConstants.Parameters.Error]?.Value<string>();
    }
}
