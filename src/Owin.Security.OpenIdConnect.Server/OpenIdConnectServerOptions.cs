/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Exposes various settings needed to control
    /// the behavior of the OpenID Connect server.
    /// </summary>
    public class OpenIdConnectServerOptions : AuthenticationOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIdConnectServerOptions"/> class.
        /// </summary>
        public OpenIdConnectServerOptions()
            : base(OpenIdConnectServerDefaults.AuthenticationType)
        {
            AuthenticationMode = AuthenticationMode.Passive;
        }

        /// <summary>
        /// Gets or sets the optional base address used to uniquely identify the authorization server.
        /// The URI must be absolute and may contain a path, but no query string or fragment part.
        /// Unless <see cref="AllowInsecureHttp"/> has been set to true, an HTTPS address must be provided.
        /// </summary>
        public Uri Issuer { get; set; }

        /// <summary>
        /// Gets the list of credentials used to encrypt the JWT access tokens issued by the
        /// OpenID Connect server handler. Note: only symmetric credentials are supported.
        /// </summary>
        public IList<EncryptingCredentials> EncryptingCredentials { get; } = new List<EncryptingCredentials>();

        /// <summary>
        /// Gets the list of credentials used to sign the JWT tokens issued by the OpenID Connect server handler.
        /// Both asymmetric and symmetric keys are supported, but only asymmetric keys can be used to sign identity tokens.
        /// Note that only asymmetric RSA and ECDSA keys can be exposed by the JWKS metadata endpoint.
        /// </summary>
        public IList<SigningCredentials> SigningCredentials { get; } = new List<SigningCredentials>();

        /// <summary>
        /// Gets or sets the request path where client applications will redirect the user-agent in order to
        /// obtain user consent to issue a token. Must begin with a leading slash (e.g "/connect/authorize").
        /// </summary>
        public PathString AuthorizationEndpointPath { get; set; }

        /// <summary>
        /// Gets or sets the request path where client applications will be able to retrieve the OpenID Connect
        /// configuration metadata. Must begin with a leading slash, (e.g "/.well-known/openid-configuration").
        /// This setting can be set to <see cref="PathString.Empty"/> to disable the configuration endpoint.
        /// </summary>
        public PathString ConfigurationEndpointPath { get; set; } = new PathString("/.well-known/openid-configuration");

        /// <summary>
        /// Gets or sets the request path where client applications will be able to retrieve the public
        /// cryptographic keys used to sign tokens. Must begin with a leading slash (e.g "/.well-known/jwks").
        /// This setting can be set to <see cref="PathString.Empty"/> to disable the cryptography endpoint.
        /// </summary>
        public PathString CryptographyEndpointPath { get; set; } = new PathString("/.well-known/jwks");

        /// <summary>
        /// Gets or sets the request path client applications communicate with to introspect tokens.
        /// Must begin with a leading slash (e.g "/connect/introspect").
        /// </summary>
        public PathString IntrospectionEndpointPath { get; set; }

        /// <summary>
        /// Gets or sets the request path client applications communicate with to log out.
        /// Must begin with a leading slash (e.g "/connect/logout").
        /// </summary>
        public PathString LogoutEndpointPath { get; set; }

        /// <summary>
        /// Gets or sets the request path client applications communicate with
        /// to revoke tokens. Must begin with a leading slash (e.g "/connect/revoke").
        /// </summary>
        public PathString RevocationEndpointPath { get; set; }

        /// <summary>
        /// Gets or sets the request path client applications communicate with to retrieve
        /// an access token. Must begin with a leading slash (e.g "/connect/token").
        /// </summary>
        public PathString TokenEndpointPath { get; set; }

        /// <summary>
        /// Gets or sets the request path client applications communicate with to retrieve
        /// user information. Must begin with a leading slash (e.g "/connect/userinfo").
        /// </summary>
        public PathString UserinfoEndpointPath { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="OpenIdConnectServerProvider"/> that the OpenID Connect server
        /// invokes to enable developer control over the entire authentication/authorization process.
        /// </summary>
        public OpenIdConnectServerProvider Provider { get; set; } = new OpenIdConnectServerProvider();

        /// <summary>
        /// Gets or sets the ticket format used to serialize and encrypt the
        /// authorization codes issued by the OpenID Connect server middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AuthorizationCodeFormat { get; set; }

        /// <summary>
        /// Gets or sets the ticket format used to serialize and encrypt the
        /// access tokens issued by the OpenID Connect server middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        /// <summary>
        /// Gets or sets the ticket format used to serialize and encrypt the
        /// refresh tokens issued by the OpenID Connect server middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> RefreshTokenFormat { get; set; }

        /// <summary>
        /// Gets or sets the optional security token handler used to serialize
        /// and the access tokens issued by the OpenID Connect server middleware.
        /// </summary>
        public JwtSecurityTokenHandler AccessTokenHandler { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to serialize and
        /// the identity tokens issued by the OpenID Connect server middleware.
        /// </summary>
        public JwtSecurityTokenHandler IdentityTokenHandler { get; set; } = new JwtSecurityTokenHandler
        {
            InboundClaimTypeMap = new Dictionary<string, string>(),
            OutboundClaimTypeMap = new Dictionary<string, string>()
        };

        /// <summary>
        /// Gets or sets the period of time the authorization codes remain valid after being issued.
        /// While not recommended, this property can be set to <c>null</c> to issue codes that never expire.
        /// </summary>
        public TimeSpan? AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Gets or sets the period of time access tokens remain valid after being issued. The default value is 1 hour.
        /// The client application is expected to refresh or acquire a new access token after the token has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue access tokens that never expire.
        /// </summary>
        public TimeSpan? AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// Gets or sets the period of time identity tokens remain valid after being issued. The default value is 20 minutes.
        /// The client application is expected to refresh or acquire a new identity token after the token has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue identity tokens that never expire.
        /// </summary>
        public TimeSpan? IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(20);

        /// <summary>
        /// Gets or sets the period of time refresh tokens remain valid after being issued. The default value is 14 days.
        /// The client application is expected to start a whole new authentication flow after the refresh token has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue refresh tokens that never expire.
        /// </summary>
        public TimeSpan? RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

        /// <summary>
        /// Gets or sets a boolean indicating whether new refresh tokens should be issued during a refresh token request.
        /// Set this property to <c>true</c> to issue a new refresh token, <c>false</c> to prevent the OpenID Connect
        /// server middleware from issuing new refresh tokens when receiving a grant_type=refresh_token request.
        /// </summary>
        public bool UseSlidingExpiration { get; set; } = true;

        /// <summary>
        /// Gets or sets a boolean indicating whether the web application is able
        /// to render error messages on the authorization and logout endpoints.
        /// </summary>
        public bool ApplicationCanDisplayErrors { get; set; }

        /// <summary>
        /// Gets or sets the system clock used by the OpenID Connect server middleware to determine the current time.
        /// If necessary, the default instance can be replaced by a mocked clock for unit testing purposes.
        /// </summary>
        public ISystemClock SystemClock { get; set; } = new SystemClock();

        /// <summary>
        /// Gets or sets a boolean indicating whether incoming requests arriving on non-HTTPS endpoints should be rejected.
        /// By default, this property is set to <c>false</c> to help mitigate man-in-the-middle attacks.
        /// </summary>
        public bool AllowInsecureHttp { get; set; }

        /// <summary>
        /// Gets or sets the encoder used to sanitize HTML responses. If no explicit instance is provided,
        /// a default instance is automatically retrieved through the dependency injection system.
        /// </summary>
        public HtmlEncoder HtmlEncoder { get; set; } = HtmlEncoder.Default;

        /// <summary>
        /// Gets or sets the data protection provider used to create the default
        /// data protectors used by the OpenID Connect server handler.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// Gets or sets the logger used by the OpenID Connect server handler.
        /// When unassigned, a default instance is created using the default logger factory.
        /// </summary>
        public ILogger Logger { get; set; }
    }
}
