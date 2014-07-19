// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Default values used by authorization server and bearer authentication.
    /// </summary>
    public static class OpenIdConnectDefaults {
        /// <summary>
        /// Default value for AuthenticationType property in the OpenIdConnectBearerAuthenticationOptions and
        /// OpenIdConnectServerOptions.
        /// </summary>
        public const string AuthenticationType = "Bearer";
    }
}
