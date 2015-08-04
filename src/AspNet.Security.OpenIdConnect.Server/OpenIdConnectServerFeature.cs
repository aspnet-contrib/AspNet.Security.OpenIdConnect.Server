/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    public class OpenIdConnectServerFeature : IOpenIdConnectServerFeature {
        public OpenIdConnectMessage Request { get; set; }
        public OpenIdConnectMessage Response { get; set; }
    }
}
