/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server.Messages {
    /// <summary>
    /// Data object representing the information contained in form encoded body of a Token endpoint request.
    /// </summary>
    public class TokenEndpointRequest {
        /// <summary>
        /// Creates a new instance populated with values from the form encoded body parameters.
        /// </summary>
        /// <param name="parameters">Form encoded body parameters from a request.</param>
        public TokenEndpointRequest(IReadableStringCollection parameters) {
            if (parameters == null) {
                throw new ArgumentNullException("parameters");
            }

            Func<string, string> getParameter = parameters.Get;

            Parameters = parameters;
            GrantType = getParameter(OpenIdConnectConstants.Parameters.GrantType);
            ClientId = getParameter(OpenIdConnectConstants.Parameters.ClientId);
            if (String.Equals(GrantType, OpenIdConnectConstants.GrantTypes.AuthorizationCode, StringComparison.Ordinal)) {
                AuthorizationCodeGrant = new TokenEndpointRequestAuthorizationCode {
                    Code = getParameter(OpenIdConnectConstants.Parameters.Code),
                    RedirectUri = getParameter(OpenIdConnectConstants.Parameters.RedirectUri),
                };
            }
            else if (String.Equals(GrantType, OpenIdConnectConstants.GrantTypes.ClientCredentials, StringComparison.Ordinal)) {
                ClientCredentialsGrant = new TokenEndpointRequestClientCredentials {
                    Scope = (getParameter(OpenIdConnectConstants.Parameters.Scope) ?? string.Empty).Split(' ')
                };
            }
            else if (String.Equals(GrantType, OpenIdConnectConstants.GrantTypes.RefreshToken, StringComparison.Ordinal)) {
                RefreshTokenGrant = new TokenEndpointRequestRefreshToken {
                    RefreshToken = getParameter(OpenIdConnectConstants.Parameters.RefreshToken),
                    Scope = (getParameter(OpenIdConnectConstants.Parameters.Scope) ?? string.Empty).Split(' ')
                };
            }
            else if (String.Equals(GrantType, OpenIdConnectConstants.GrantTypes.Password, StringComparison.Ordinal)) {
                ResourceOwnerPasswordCredentialsGrant = new TokenEndpointRequestResourceOwnerPasswordCredentials {
                    UserName = getParameter(OpenIdConnectConstants.Parameters.Username),
                    Password = getParameter(OpenIdConnectConstants.Parameters.Password),
                    Scope = (getParameter(OpenIdConnectConstants.Parameters.Scope) ?? string.Empty).Split(' ')
                };
            }
            else if (!String.IsNullOrEmpty(GrantType)) {
                CustomExtensionGrant = new TokenEndpointRequestCustomExtension {
                    Parameters = parameters,
                };
            }
        }

        /// <summary>
        /// The form encoded body parameters of the Token endpoint request
        /// </summary>
        public IReadableStringCollection Parameters { get; private set; }

        /// <summary>
        /// The "grant_type" parameter of the Token endpoint request. This parameter is required.
        /// </summary>
        public string GrantType { get; private set; }

        /// <summary>
        /// The "client_id" parameter of the Token endpoint request. This parameter is optional. It might not
        /// be present if the request is authenticated in a different way, for example, by using basic authentication
        /// credentials.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// Data object available when the "grant_type" is "authorization_code".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.1.3
        /// </summary>    
        public TokenEndpointRequestAuthorizationCode AuthorizationCodeGrant { get; private set; }

        /// <summary>
        /// Data object available when the "grant_type" is "client_credentials".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.4.2
        /// </summary>    
        public TokenEndpointRequestClientCredentials ClientCredentialsGrant { get; private set; }

        /// <summary>
        /// Data object available when the "grant_type" is "refresh_token".
        /// See also http://tools.ietf.org/html/rfc6749#section-6
        /// </summary>    
        public TokenEndpointRequestRefreshToken RefreshTokenGrant { get; private set; }

        /// <summary>
        /// Data object available when the "grant_type" is "password".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>    
        public TokenEndpointRequestResourceOwnerPasswordCredentials ResourceOwnerPasswordCredentialsGrant { get; private set; }

        /// <summary>
        /// Data object available when the "grant_type" is unrecognized.
        /// See also http://tools.ietf.org/html/rfc6749#section-4.5
        /// </summary>
        public TokenEndpointRequestCustomExtension CustomExtensionGrant { get; private set; }

        /// <summary>
        /// True when the "grant_type" is "authorization_code".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.1.3
        /// </summary>    
        public bool IsAuthorizationCodeGrantType {
            get { return AuthorizationCodeGrant != null; }
        }

        /// <summary>
        /// True when the "grant_type" is "client_credentials".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.4.2
        /// </summary>  
        public bool IsClientCredentialsGrantType {
            get { return ClientCredentialsGrant != null; }
        }

        /// <summary>
        /// True when the "grant_type" is "refresh_token".
        /// See also http://tools.ietf.org/html/rfc6749#section-6
        /// </summary>    
        public bool IsRefreshTokenGrantType {
            get { return RefreshTokenGrant != null; }
        }

        /// <summary>
        /// True when the "grant_type" is "password".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>    
        public bool IsResourceOwnerPasswordCredentialsGrantType {
            get { return ResourceOwnerPasswordCredentialsGrant != null; }
        }

        /// <summary>
        /// True when the "grant_type" is unrecognized.
        /// See also http://tools.ietf.org/html/rfc6749#section-4.5
        /// </summary>
        public bool IsCustomExtensionGrantType {
            get { return CustomExtensionGrant != null; }
        }
    }
}
