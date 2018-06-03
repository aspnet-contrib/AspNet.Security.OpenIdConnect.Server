/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.HandleConfigurationRequest"/> event.
    /// </summary>
    public class HandleConfigurationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleConfigurationRequestContext"/> class.
        /// </summary>
        public HandleConfigurationRequestContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, scheme, options, request)
        {
            Validate();
        }

        /// <summary>
        /// Gets the additional parameters returned to the client application.
        /// </summary>
        public IDictionary<string, OpenIdConnectParameter> Metadata { get; } =
            new Dictionary<string, OpenIdConnectParameter>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the authorization endpoint address.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the JWKS endpoint address.
        /// </summary>
        public string CryptographyEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the introspection endpoint address.
        /// </summary>
        public string IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the logout endpoint address.
        /// </summary>
        public string LogoutEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the revocation endpoint address.
        /// </summary>
        public string RevocationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the token endpoint address.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the userinfo endpoint address.
        /// </summary>
        public string UserinfoEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets the list of claims supported by the authorization server.
        /// </summary>
        public ISet<string> Claims { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of the code challenge methods
        /// supported by the authorization server.
        /// </summary>
        public ISet<string> CodeChallengeMethods { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of grant types
        /// supported by the authorization server.
        /// </summary>
        public ISet<string> GrantTypes { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of signing algorithms supported by the
        /// authorization server for signing the identity tokens.
        /// </summary>
        public ISet<string> IdTokenSigningAlgorithms { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by
        /// the introspection endpoint provided by the authorization server.
        /// </summary>
        public ISet<string> IntrospectionEndpointAuthenticationMethods { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of response modes
        /// supported by the authorization server.
        /// </summary>
        public ISet<string> ResponseModes { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of response types
        /// supported by the authorization server.
        /// </summary>
        public ISet<string> ResponseTypes { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by
        /// the revocation endpoint provided by the authorization server.
        /// </summary>
        public ISet<string> RevocationEndpointAuthenticationMethods { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of scope values
        /// supported by the authorization server.
        /// </summary>
        public ISet<string> Scopes { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of subject types
        /// supported by the authorization server.
        /// </summary>
        public ISet<string> SubjectTypes { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by
        /// the token endpoint provided by the authorization server.
        /// </summary>
        public ISet<string> TokenEndpointAuthenticationMethods { get; } =
            new HashSet<string>(StringComparer.Ordinal);
    }
}
