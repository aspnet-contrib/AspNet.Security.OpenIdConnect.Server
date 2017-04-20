/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.ApplyAuthorizationResponse"/> event.
    /// </summary>
    public class ApplyAuthorizationResponseContext : HandleRequestContext<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyAuthorizationResponseContext"/> class.
        /// </summary>
        public ApplyAuthorizationResponseContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response)
            : base(context, scheme, options)
        {
            Ticket = ticket;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the authorization request.
        /// </summary>
        /// <remarks>
        /// Note: this property may be null if an error occurred while
        /// extracting the authorization request from the HTTP request.
        /// </remarks>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the authorization response.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        /// <summary>
        /// Gets the access code expected to
        /// be returned to the client application.
        /// Depending on the flow, it may be null.
        /// </summary>
        public string AccessToken => Response.AccessToken;

        /// <summary>
        /// Gets the authorization code expected to
        /// be returned to the client application.
        /// Depending on the flow, it may be null.
        /// </summary>
        public string AuthorizationCode => Response.Code;

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <c>null</c>.
        /// </summary>
        public string Error => Response.Error;

        /// <summary>
        /// Gets or sets the callback URL the user agent will be redirected to, if applicable.
        /// Note: manually changing the value of this property is generally not recommended
        /// and extreme caution must be taken to ensure the user agent is not redirected to
        /// an untrusted address, which would result in an "open redirection" vulnerability.
        /// </summary>
        public string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the response mode used to redirect the user agent, if applicable.
        /// Note: manually changing the value of this property is generally not recommended.
        /// </summary>
        public string ResponseMode { get; set; }
    }
}
