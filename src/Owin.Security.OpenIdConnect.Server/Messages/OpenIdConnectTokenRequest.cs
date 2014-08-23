/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server.Messages {
    /// <summary>
    /// Data object representing the information contained in form encoded body of a Token endpoint request.
    /// </summary>
    public class OpenIdConnectTokenRequest {
        /// <summary>
        /// Creates a new instance populated with values from the form encoded body parameters.
        /// </summary>
        /// <param name="parameters">Form encoded body parameters from a request.</param>
        public OpenIdConnectTokenRequest(IReadableStringCollection parameters) {
            if (parameters == null) {
                throw new ArgumentNullException("parameters");
            }

            Parameters = parameters;
            GrantType = parameters.Get(OpenIdConnectConstants.Parameters.GrantType);
            ClientId = parameters.Get(OpenIdConnectConstants.Parameters.ClientId);

            if (IsAuthorizationCodeGrantType) {
                Code = parameters.Get(OpenIdConnectConstants.Parameters.Code);
                RedirectUri = parameters.Get(OpenIdConnectConstants.Parameters.RedirectUri);
            }

            if (IsRefreshTokenGrantType) {
                RefreshToken = parameters.Get(OpenIdConnectConstants.Parameters.RefreshToken);
            }

            if (IsResourceOwnerPasswordCredentialsGrantType) {
                UserName = parameters.Get(OpenIdConnectConstants.Parameters.Username);
                Password = parameters.Get(OpenIdConnectConstants.Parameters.Password);
            }

            if (IsClientCredentialsGrantType || IsRefreshTokenGrantType || IsResourceOwnerPasswordCredentialsGrantType) {
                Scope = (parameters.Get(OpenIdConnectConstants.Parameters.Scope) ?? string.Empty).Split(' ');
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
        /// The value passed to the Token endpoint in the "code" parameter
        /// </summary>
        public string Code { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "redirect_uri" parameter. This MUST be provided by
        /// the caller if the original visit to the authorization endpoint contained a "redirect_uri" parameter.
        /// </summary>
        [SuppressMessage("Microsoft.Design",
            "CA1056:UriPropertiesShouldNotBeStrings",
            Justification = "By design")]
        public string RedirectUri { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "scope" parameter
        /// </summary>
        [SuppressMessage("Microsoft.Usage",
            "CA2227:CollectionPropertiesShouldBeReadOnly",
            Justification = "This class is just for passing data through.")]
        public IList<string> Scope { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "refresh_token" parameter
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "username" parameter
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// The value passed to the Token endpoint in the "password" parameter
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// True when the "grant_type" is "authorization_code".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.1.3
        /// </summary>    
        public bool IsAuthorizationCodeGrantType {
            get { return string.Equals(GrantType, OpenIdConnectConstants.GrantTypes.AuthorizationCode, StringComparison.Ordinal); }
        }

        /// <summary>
        /// True when the "grant_type" is "client_credentials".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.4.2
        /// </summary>  
        public bool IsClientCredentialsGrantType {
            get { return string.Equals(GrantType, OpenIdConnectConstants.GrantTypes.ClientCredentials, StringComparison.Ordinal); }
        }

        /// <summary>
        /// True when the "grant_type" is "refresh_token".
        /// See also http://tools.ietf.org/html/rfc6749#section-6
        /// </summary>    
        public bool IsRefreshTokenGrantType {
            get { return string.Equals(GrantType, OpenIdConnectConstants.GrantTypes.RefreshToken, StringComparison.Ordinal); }
        }

        /// <summary>
        /// True when the "grant_type" is "password".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>    
        public bool IsResourceOwnerPasswordCredentialsGrantType {
            get { return string.Equals(GrantType, OpenIdConnectConstants.GrantTypes.Password, StringComparison.Ordinal); }
        }

        /// <summary>
        /// True when the "grant_type" is unrecognized.
        /// See also http://tools.ietf.org/html/rfc6749#section-4.5
        /// </summary>
        public bool IsCustomExtensionGrantType {
            get { return !string.IsNullOrEmpty(GrantType); }
        }
    }
}
