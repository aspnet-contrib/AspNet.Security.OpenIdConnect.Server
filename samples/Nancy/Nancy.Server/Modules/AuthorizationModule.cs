using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Nancy.Security;
using Nancy.Server.Extensions;
using Nancy.Server.Models;
using Owin;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server.Modules {
    public class AuthorizationModule : NancyModule {
        public AuthorizationModule() {
            Get["/connect/authorize", runAsync: true] =
            Post["/connect/authorize", runAsync: true] = async (parameters, cancellationToken) => {
                this.CreateNewCsrfToken();
                
                // Note: when a fatal error occurs during the request processing, an OpenID Connect response
                // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
                // When the user agent can be safely redirected to the client application,
                // OpenIdConnectServerHandler automatically handles the error and Nancy is not invoked.
                // You can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
                // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
                var response = OwinContext.GetOpenIdConnectResponse();
                if (response != null) {
                    return View["Error.cshtml", response];
                }

                // Extract the authorization request from the OWIN environment.
                var request = OwinContext.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["Error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_request",
                        ErrorDescription = "An internal error has occurred"
                    }];
                }

                // Note: authentication could be theorically enforced at the filter level via AuthorizeAttribute
                // but this authorization endpoint accepts both GET and POST requests while the cookie middleware
                // only uses 302 responses to redirect the user agent to the login page, making it incompatible with POST.
                // To work around this limitation, the OpenID Connect request is automatically saved in the cache and will be
                // restored in the other "Authorize" method, after the authentication process has been completed.
                if (OwinContext.Authentication.User?.Identity == null ||
                   !OwinContext.Authentication.User.Identity.IsAuthenticated) {
                    return Response.AsRedirect("/signin?returnUrl=" + Uri.EscapeUriString("/connect/authorize?unique_id=" +
                                                                                          request.GetUniqueIdentifier()));
                }

                // Note: Owin.Security.OpenIdConnect.Server automatically ensures an application
                // corresponds to the client_id specified in the authorization request using
                // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see CustomOpenIdConnectServerProvider.cs).
                // In theory, this null check is thus not strictly necessary. That said, a race condition
                // and a null reference exception could appear here if you manually removed the application
                // details from the database after the initial check made by Owin.Security.OpenIdConnect.Server.
                var application = await GetApplicationAsync(request.ClientId, cancellationToken);
                if (application == null) {
                    return View["Error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_client",
                        ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                    }];
                }

                // Note: in a real world application, you'd probably
                // prefer creating a specific view model.
                return View["Authorize.cshtml", new {
                    Application = application,
                    Request = request,
                    Resources = request.GetResources(),
                    UniqueId = request.GetUniqueIdentifier()
                }];
            };
            
            Post["/connect/authorize/accept", runAsync: true] = async (parameters, cancellationToken) => {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                // Extract the authorization request from the cache, the query string or the request form.
                var request = OwinContext.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["Error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_request",
                        ErrorDescription = "An internal error has occurred"
                    }];
                }
                
                // Create a new ClaimsIdentity containing the claims that
                // will be used to create an id_token, a token or a code.
                var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationType);

                foreach (var claim in OwinContext.Authentication.User.Claims) {
                    // Allow ClaimTypes.Name to be added in the id_token.
                    // ClaimTypes.NameIdentifier is automatically added, even if its
                    // destination is not defined or doesn't include "id_token".
                    // The other claims won't be visible for the client application.
                    if (claim.Type == ClaimTypes.Name) {
                        claim.SetDestinations(OpenIdConnectConstants.Destinations.AccessToken,
                                              OpenIdConnectConstants.Destinations.IdentityToken);
                    }

                    identity.AddClaim(claim);
                }

                // Note: Owin.Security.OpenIdConnect.Server automatically ensures an application
                // corresponds to the client_id specified in the authorization request using
                // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see AuthorizationProvider.cs).
                // In theory, this null check is thus not strictly necessary. That said, a race condition
                // and a null reference exception could appear here if you manually removed the application
                // details from the database after the initial check made by Owin.Security.OpenIdConnect.Server.
                var application = await GetApplicationAsync(request.ClientId, CancellationToken.None);
                if (application == null) {
                    return View["Error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_client",
                        ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                    }];
                }

                // Create a new ClaimsIdentity containing the claims associated with the application.
                // Note: setting identity.Actor is not mandatory but can be useful to access
                // the whole delegation chain from the resource server (see ResourceController.cs).
                identity.Actor = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationType);
                identity.Actor.AddClaim(ClaimTypes.NameIdentifier, application.ApplicationID);

                identity.Actor.AddClaim(ClaimTypes.Name, application.DisplayName,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);

                // Create a new authentication ticket holding the user identity.
                var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                // Set the list of scopes granted to the client application.
                // Note: this sample always grants the "openid", "email" and "profile" scopes
                // when they are requested by the client application: a real world application
                // would probably display a form allowing to select the scopes to grant.
                ticket.SetScopes(new[] {
                    /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                    /* email: */ OpenIdConnectConstants.Scopes.Email,
                    /* profile: */ OpenIdConnectConstants.Scopes.Profile
                }.Intersect(request.GetScopes()));

                // Set the resources servers the access token should be issued for.
                ticket.SetResources("resource_server");

                // This call will instruct Owin.Security.OpenIdConnect.Server to serialize
                // the specified identity to build appropriate tokens (id_token and token).
                // Note: you should always make sure the identities you return contain either
                // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
                // identities always contain the name identifier returned by the external provider.
                OwinContext.Authentication.SignIn(ticket.Properties, ticket.Identity);

                return HttpStatusCode.OK;
            };

            Post["/connect/authorize/deny"] = parameters => {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                // Extract the authorization request from the cache, the query string or the request form.
                var request = OwinContext.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["Error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_request",
                        ErrorDescription = "An internal error has occurred"
                    }];
                }

                // Notify Owin.Security.OpenIdConnect.Server that the authorization grant has been denied.
                // Note: OpenIdConnectServerHandler will automatically take care of redirecting
                // the user agent to the client application using the appropriate response_mode.
                OwinContext.SetOpenIdConnectResponse(new OpenIdConnectMessage {
                    Error = "access_denied",
                    ErrorDescription = "The authorization grant has been denied by the resource owner",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });

                return HttpStatusCode.OK;
            };

            Get["/connect/logout", runAsync: true] = async (parameters, cancellationToken) => {
                // Note: when a fatal error occurs during the request processing, an OpenID Connect response
                // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
                // In this case, the OpenID Connect request is null and cannot be used.
                // When the user agent can be safely redirected to the client application,
                // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
                // You can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
                // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
                var response = OwinContext.GetOpenIdConnectResponse();
                if (response != null) {
                    return View["Error.cshtml", response];
                }

                // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
                // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
                // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
                var identity = await OwinContext.Authentication.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationType);

                // Extract the logout request from the OWIN environment.
                var request = OwinContext.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["Error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_request",
                        ErrorDescription = "An internal error has occurred"
                    }];
                }

                return View["Logout.cshtml", Tuple.Create(request, identity)];
            };

            Post["/connect/logout"] = parameters => {
                this.ValidateCsrfToken();

                // Instruct the cookies middleware to delete the local cookie created
                // when the user agent is redirected from the external identity provider
                // after a successful authentication flow (e.g Google or Facebook).
                OwinContext.Authentication.SignOut("ServerCookie");

                // This call will instruct Owin.Security.OpenIdConnect.Server to serialize
                // the specified identity to build appropriate tokens (id_token and token).
                // Note: you should always make sure the identities you return contain either
                // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
                // identities always contain the name identifier returned by the external provider.
                OwinContext.Authentication.SignOut(OpenIdConnectServerDefaults.AuthenticationType);

                return HttpStatusCode.OK;
            };
        }

        /// <summary>
        /// Gets the IOwinContext instance associated with the current request.
        /// </summary>
        protected IOwinContext OwinContext {
            get {
                var context = Context.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                return context;
            }
        }
        
        protected async Task<Application> GetApplicationAsync(string identifier, CancellationToken cancellationToken) {
            using (var context = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                return await (from application in context.Applications
                              where application.ApplicationID == identifier
                              select application).SingleOrDefaultAsync(cancellationToken);
            }
        }
    }
}