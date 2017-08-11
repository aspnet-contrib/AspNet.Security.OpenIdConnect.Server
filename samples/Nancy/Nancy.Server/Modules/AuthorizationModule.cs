using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Nancy.Security;
using Nancy.Server.Extensions;
using Nancy.Server.Models;
using Owin;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server.Modules
{
    public class AuthorizationModule : NancyModule
    {
        public AuthorizationModule()
        {
            Get["/connect/authorize", runAsync: true] = async (parameters, cancellationToken) =>
            {
                this.CreateNewCsrfToken();
                this.RequiresMSOwinAuthentication();

                // Note: when a fatal error occurs during the request processing, an OpenID Connect response
                // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
                // You can safely remove this part and let ASOS automatically handle the unrecoverable errors
                // by switching ApplicationCanDisplayErrors to false in Startup.cs.
                var response = OwinContext.GetOpenIdConnectResponse();
                if (response != null)
                {
                    return View["Error.cshtml", response];
                }

                // Extract the authorization request from the OWIN environment.
                var request = OwinContext.GetOpenIdConnectRequest();
                if (request == null)
                {
                    return View["Error.cshtml", new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "An internal error has occurred."
                    }];
                }

                // Note: ASOS automatically ensures that an application corresponds to the client_id specified
                // in the authorization request by calling OpenIdConnectServerProvider.ValidateAuthorizationRequest.
                // In theory, this null check shouldn't be needed, but a race condition could occur if you
                // manually removed the application details from the database after the initial check made by ASOS.
                var application = await GetApplicationAsync(request.ClientId, cancellationToken);
                if (application == null)
                {
                    return View["Error.cshtml", new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidClient,
                        ErrorDescription = "The specified client identifier is invalid."
                    }];
                }

                // Note: in a real world application, you'd probably
                // prefer creating a specific view model.
                return View["Authorize.cshtml", Tuple.Create(request, application)];
            };

            Post["/connect/authorize/accept", runAsync: true] = async (parameters, cancellationToken) =>
            {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                var response = OwinContext.GetOpenIdConnectResponse();
                if (response != null)
                {
                    return View["Error.cshtml", response];
                }

                var request = OwinContext.GetOpenIdConnectRequest();
                if (request == null)
                {
                    return View["Error.cshtml", new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "An internal error has occurred."
                    }];
                }

                // Create a new ClaimsIdentity containing the claims that
                // will be used to create an id_token, a token or a code.
                var identity = new ClaimsIdentity(
                    OpenIdConnectServerDefaults.AuthenticationType,
                    OpenIdConnectConstants.Claims.Name,
                    OpenIdConnectConstants.Claims.Role);

                // Note: the "sub" claim is mandatory and an
                // exception is thrown if this claim is missing.
                identity.AddClaim(
                    new Claim(OpenIdConnectConstants.Claims.Subject, User.FindFirst(ClaimTypes.NameIdentifier).Value)
                        .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken,
                                         OpenIdConnectConstants.Destinations.IdentityToken));

                identity.AddClaim(
                    new Claim(OpenIdConnectConstants.Claims.Name, User.FindFirst(ClaimTypes.Name).Value)
                        .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken,
                                         OpenIdConnectConstants.Destinations.IdentityToken));

                var application = await GetApplicationAsync(request.ClientId, CancellationToken.None);
                if (application == null)
                {
                    return View["Error.cshtml", new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The specified client identifier is invalid."
                    }];
                }

                // Create a new authentication ticket holding the user identity.
                var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                // Set the list of scopes granted to the client application.
                // Note: this sample always grants the "openid", "email" and "profile" scopes
                // when they are requested by the client application: a real world application
                // would probably display a form allowing to select the scopes to grant.
                ticket.SetScopes(new[]
                {
                    /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                    /* email: */ OpenIdConnectConstants.Scopes.Email,
                    /* profile: */ OpenIdConnectConstants.Scopes.Profile,
                    /* offline_access: */ OpenIdConnectConstants.Scopes.OfflineAccess
                }.Intersect(request.GetScopes()));

                // Set the resources servers the access token should be issued for.
                ticket.SetResources("resource_server");

                // This call will ask ASOS to serialize the specified identity to build appropriate tokens.
                OwinContext.Authentication.SignIn(ticket.Properties, ticket.Identity);

                return HttpStatusCode.OK;
            };

            Post["/connect/authorize/deny"] = parameters =>
            {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                var response = OwinContext.GetOpenIdConnectResponse();
                if (response != null)
                {
                    return View["Error.cshtml", response];
                }

                // Notify ASOS that the authorization grant has been denied by the resource owner.
                // Note: OpenIdConnectServerHandler will automatically take care of redirecting
                // the user agent to the client application using the appropriate response_mode.
                OwinContext.Authentication.Challenge(OpenIdConnectServerDefaults.AuthenticationType);

                return HttpStatusCode.Forbidden;
            };

            Get["/connect/logout", runAsync: true] = async (parameters, cancellationToken) =>
            {
                var response = OwinContext.GetOpenIdConnectResponse();
                if (response != null)
                {
                    return View["Error.cshtml", response];
                }

                // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
                // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
                // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
                var identity = await OwinContext.Authentication.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationType);

                // Extract the logout request from the OWIN environment.
                var request = OwinContext.GetOpenIdConnectRequest();
                if (request == null)
                {
                    return View["Error.cshtml", new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "An internal error has occurred."
                    }];
                }

                return View["Logout.cshtml", Tuple.Create(request, identity)];
            };

            Post["/connect/logout"] = parameters =>
            {
                this.ValidateCsrfToken();

                var response = OwinContext.GetOpenIdConnectResponse();
                if (response != null)
                {
                    return View["Error.cshtml", response];
                }

                // Ask the cookies middleware to delete the local cookie created
                // when the user agent is redirected from the external identity provider
                // after a successful authentication flow (e.g Google or Facebook) and
                // redirect the user agent to the post_logout_redirect_uri specified by the client application.
                OwinContext.Authentication.SignOut("ServerCookie", OpenIdConnectServerDefaults.AuthenticationType);

                return HttpStatusCode.OK;
            };
        }

        /// <summary>
        /// Gets the IOwinContext instance associated with the current request.
        /// </summary>
        private IOwinContext OwinContext
        {
            get
            {
                var context = Context.GetOwinContext();
                if (context == null)
                {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                return context;
            }
        }

        /// <summary>
        /// Gets the <see cref="ClaimsPrincipal"/> instance associated with the current request.
        /// </summary>
        private ClaimsPrincipal User => OwinContext.Authentication.User;

        private async Task<Application> GetApplicationAsync(string identifier, CancellationToken cancellationToken)
        {
            using (var context = new ApplicationContext())
            {
                // Retrieve the application details corresponding to the requested client_id.
                return await (from application in context.Applications
                              where application.ApplicationID == identifier
                              select application).SingleOrDefaultAsync(cancellationToken);
            }
        }
    }
}
