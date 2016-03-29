using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Mvc.Server.Models;

namespace Mvc.Server.Controllers {
    public class AuthorizationController : Controller {
        private readonly ApplicationContext database;

        public AuthorizationController(ApplicationContext database) {
            this.database = database;
        }
        
        [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize(CancellationToken cancellationToken) {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
            // You can safely remove this part and let ASOS automatically handle the unrecoverable errors
            // by switching ApplicationCanDisplayErrors to false in Startup.cs.
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // Extract the authorization request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Note: authentication could be theorically enforced at the filter level via AuthorizeAttribute
            // but this authorization endpoint accepts both GET and POST requests while the cookie middleware
            // only uses 302 responses to redirect the user agent to the login page, making it incompatible with POST.
            // To work around this limitation, the OpenID Connect request is automatically saved in the cache and will be
            // restored by the OpenID Connect server middleware after the external authentication process has been completed.
            if (!User.Identities.Any(identity => identity.IsAuthenticated)) {
                return Challenge(new AuthenticationProperties {
                    RedirectUri = Url.Action(nameof(Authorize), new {
                        request_id = request.GetRequestIdentifier()
                    })
                });
            }

            // Note: ASOS automatically ensures that an application corresponds to the client_id specified
            // in the authorization request by calling IOpenIdConnectServerProvider.ValidateAuthorizationRequest.
            // In theory, this null check shouldn't be needed, but a race condition could occur if you
            // manually removed the application details from the database after the initial check made by ASOS.
            var application = await GetApplicationAsync(request.ClientId, cancellationToken);
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Note: in a real world application, you'd probably prefer creating a specific view model.
            return View("Authorize", Tuple.Create(request, application));
        }

        [Authorize, HttpPost("~/connect/authorize/accept"), ValidateAntiForgeryToken]
        public async Task<IActionResult> Accept(CancellationToken cancellationToken) {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);

            // Copy the claims retrieved from the external identity provider
            // (e.g Google, Facebook, a WS-Fed provider or another OIDC server).
            foreach (var claim in HttpContext.User.Claims) {
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

            var application = await GetApplicationAsync(request.ClientId, cancellationToken);
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Create a new ClaimsIdentity containing the claims associated with the application.
            // Note: setting identity.Actor is not mandatory but can be useful to access
            // the whole delegation chain from the resource server (see ResourceController.cs).
            identity.Actor = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.Actor.AddClaim(ClaimTypes.NameIdentifier, application.ApplicationID);

            identity.Actor.AddClaim(ClaimTypes.Name, application.DisplayName,
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

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

            // Returning a SignInResult will ask ASOS to serialize the specified identity to build appropriate tokens.
            // Note: you should always make sure the identities you return contain ClaimTypes.NameIdentifier claim.
            // In this sample, the identity always contains the name identifier returned by the external provider.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        [Authorize, HttpPost("~/connect/authorize/deny"), ValidateAntiForgeryToken]
        public IActionResult Deny(CancellationToken cancellationToken) {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Notify ASOS that the authorization grant has been denied by the resource owner.
            // Note: OpenIdConnectServerHandler will automatically take care of redirecting
            // the user agent to the client application using the appropriate response_mode.
            return Forbid(OpenIdConnectServerDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/logout")]
        public async Task<ActionResult> Logout(CancellationToken cancellationToken) {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
            // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
            // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
            var identity = await HttpContext.Authentication.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationScheme);

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            return View("Logout", Tuple.Create(request, identity));
        }

        [HttpPost("~/connect/logout")]
        [ValidateAntiForgeryToken]
        public ActionResult Logout() {
            // Returning a SignOutResult will ask the cookies middleware to delete the local cookie created when
            // the user agent is redirected from the external identity provider after a successful authentication flow
            // and will redirect the user agent to the post_logout_redirect_uri specified by the client application.
            return SignOut("ServerCookie", OpenIdConnectServerDefaults.AuthenticationScheme);
        }
        
        protected virtual Task<Application> GetApplicationAsync(string identifier, CancellationToken cancellationToken) {
            // Retrieve the application details corresponding to the requested client_id.
            return (from application in database.Applications
                    where application.ApplicationID == identifier
                    select application).SingleOrDefaultAsync(cancellationToken);
        }
    }
}