/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Options class provides information needed to control Authorization Server middleware behavior
    /// </summary>
    public class OpenIdConnectServerOptions : AuthenticationOptions {
        /// <summary>
        /// Creates an instance of authorization server options with default values.
        /// </summary>
        public OpenIdConnectServerOptions()
            : base(OpenIdConnectDefaults.AuthenticationType) {
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(5);
            AccessTokenLifetime = TimeSpan.FromMinutes(20);
            IdentityTokenLifetime = TimeSpan.FromMinutes(20);
            AuthorizationEndpointPath = new PathString(OpenIdConnectDefaults.AuthorizationEndpointPath);
            ConfigurationEndpointPath = new PathString(OpenIdConnectDefaults.ConfigurationEndpointPath);
            KeysEndpointPath = new PathString(OpenIdConnectDefaults.KeysEndpointPath);
            TokenEndpointPath = new PathString(OpenIdConnectDefaults.TokenEndpointPath);
        }

        /// <summary>
        /// The base address used to uniquely identify the authorization server.
        /// The URI must be absolute and may contain a path, but no query string or fragment part.
        /// Unless AllowInsecureHttp has been set to true, an HTTPS address must be provided.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// The credentials used to sign id_tokens. You can provide any symmetric (e.g <see cref="InMemorySymmetricSecurityKey"/>)
        /// or asymmetric (e.g <see cref="RsaSecurityKey"/>, <see cref="X509AsymmetricSecurityKey"/> or <see cref="X509SecurityKey"/>)
        /// security key, but you're strongly encouraged to use a 2048 or 4096-bits RSA asymmetric key in production.
        /// Note that only keys supporting the <see cref="SecurityAlgorithms.RsaSha256Signature"/> algorithm can be exposed
        /// on the configuration metadata endpoint. A <see cref="X509SigningCredentials"/> instance may also be provided.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// The request path where client applications will redirect the user-agent in order to 
        /// obtain user consent to issue a token. Must begin with a leading slash, like "/connect/authorize".
        /// </summary>
        public PathString AuthorizationEndpointPath { get; set; }

        /// <summary>
        /// The request path where client applications will be able to retrieve the configuration metadata associated
        /// with this instance. Must begin with a leading slash, like "/.well-known/openid-configuration".
        /// This setting can be set to <see cref="PathString.Empty"/> to disable the configuration endpoint.
        /// </summary>
        public PathString ConfigurationEndpointPath { get; set; }

        /// <summary>
        /// The request path where client applications will be able to retrieve the JSON Web Key Set
        /// associated with this instance. Must begin with a leading slash, like "/.well-known/jwks".
        /// This setting can be set to <see cref="PathString.Empty"/> to disable the crypto endpoint.
        /// </summary>
        public PathString KeysEndpointPath { get; set; }

        /// <summary>
        /// The request path client applications communicate with directly as part of the OpenID Connect protocol. 
        /// Must begin with a leading slash, like "/connect/token". If the client is issued a client_secret, it must
        /// be provided to this endpoint. You can set it to <see cref="PathString.Empty"/> to disable the token endpoint.
        /// </summary>
        public PathString TokenEndpointPath { get; set; }

        /// <summary>
        /// The object provided by the application to process events raised by the Authorization Server middleware.
        /// The application may implement the interface fully, or it may create an instance of OpenIdConnectServerProvider
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public IOpenIdConnectServerProvider Provider { get; set; }

        /// <summary>
        /// The data format used to protect and unprotect the information contained in the authorization code. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AuthorizationCodeFormat { get; set; }

        /// <summary>
        /// The data format used to protect the information contained in the access token. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection. If a different access token
        /// provider or format is assigned, a compatible instance must be assigned to the OAuthBearerAuthenticationOptions.AccessTokenProvider 
        /// or OAuthBearerAuthenticationOptions.AccessTokenFormat property of the resource server.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        /// <summary>
        /// The data format used to protect and unprotect the information contained in the refresh token. 
        /// If not provided by the application the default data protection provider depends on the host server. 
        /// The SystemWeb host on IIS will use ASP.NET machine key data protection, and HttpListener and other self-hosted
        /// servers will use DPAPI data protection.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> RefreshTokenFormat { get; set; }

        /// <summary>
        /// The period of time the authorization code remains valid after being issued. The default is five minutes.
        /// This time span must also take into account clock synchronization between servers in a web farm, so a very 
        /// brief value could result in unexpectedly expired tokens.
        /// </summary>
        public TimeSpan AuthorizationCodeLifetime { get; set; }

        /// <summary>
        /// The period of time the access token remains valid after being issued. The default is twenty minutes.
        /// The client application is expected to refresh or acquire a new access token after the token has expired. 
        /// </summary>
        public TimeSpan AccessTokenLifetime { get; set; }

        /// <summary>
        /// The period of time the identity token remains valid after being issued. The default is twenty minutes.
        /// The client application is expected to refresh or acquire a new identity token after the token has expired. 
        /// </summary>
        public TimeSpan IdentityTokenLifetime { get; set; }

        /// <summary>
        /// Produces a single-use authorization code to return to the client application. For the OpenID Connect server to be secure the
        /// application MUST provide an instance for AuthorizationCodeProvider where the token produced by the OnCreate or OnCreateAsync event 
        /// is considered valid for only one call to OnReceive or OnReceiveAsync. 
        /// </summary>
        public IAuthenticationTokenProvider AuthorizationCodeProvider { get; set; }

        /// <summary>
        /// Produces a bearer token the client application will typically be providing to resource server as the authorization bearer 
        /// http request header. If not provided the token produced on the server's default data protection. If a different access token
        /// provider or format is assigned, a compatible instance must be assigned to the OAuthBearerAuthenticationOptions.AccessTokenProvider 
        /// or OAuthBearerAuthenticationOptions.AccessTokenFormat property of the resource server.
        /// </summary>
        public IAuthenticationTokenProvider AccessTokenProvider { get; set; }

        /// <summary>
        /// Produces a refresh token which may be used to produce a new access token when needed. If not provided the authorization server will
        /// not return refresh tokens from the /Token endpoint.
        /// </summary>
        public IAuthenticationTokenProvider RefreshTokenProvider { get; set; }

        /// <summary>
        /// Set to true if the web application is able to render error messages on the authorization endpoint. This is only needed for cases where
        /// the browser is not redirected back to the client application, for example, when the client_id or redirect_uri are incorrect. The 
        /// authorization endpoint should expect to see "oauth.Error", "oauth.ErrorDescription", "oauth.ErrorUri" properties added to the owin environment.
        /// </summary>
        public bool ApplicationCanDisplayErrors { get; set; }

        /// <summary>
        /// Used to know what the current clock time is when calculating or validating token expiration. When not assigned default is based on
        /// DateTimeOffset.UtcNow. This is typically needed only for unit testing.
        /// </summary>
        public ISystemClock SystemClock { get; set; }

        /// <summary>
        /// True to allow incoming requests to arrive on HTTP and to allow redirect_uri parameters to have HTTP URI addresses.
        /// Setting this option to false in production is strongly encouraged to mitigate man-in-the-middle attacks.
        /// </summary>
        public bool AllowInsecureHttp { get; set; }

        /// <summary>
        /// The provider used to sign the identity tokens produced by the authorization server.
        /// Providing an instance is generally not required.
        /// </summary>
        /// <seealso cref="SigningCredentials"/>
        public SignatureProvider SignatureProvider { get; set; }

        /// <summary>
        /// The <see cref="JwtSecurityTokenHandler"/> instance used to forge identity tokens.
        /// You can replace the default instance to change the way id_tokens are serialized.
        /// </summary>
        public JwtSecurityTokenHandler TokenHandler { get; set; }
    }
}
