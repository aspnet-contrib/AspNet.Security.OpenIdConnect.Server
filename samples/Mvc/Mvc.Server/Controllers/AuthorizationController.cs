using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc;
using Microsoft.Data.Entity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Mvc.Server.Models;

namespace Mvc.Server.Controllers {
    public class AuthorizationController : Controller {
        private readonly ApplicationContext database;

        public AuthorizationController(ApplicationContext database) {
            this.database = database;
        }
        
        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize(CancellationToken cancellationToken) {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let AspNet.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // Extract the authorization request from the cache, the query string or the request form.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Note: authentication could be theorically enforced at the filter level via AuthorizeAttribute
            // but this authorization endpoint accepts both GET and POST requests while the cookie middleware
            // only uses 302 responses to redirect the user agent to the login page, making it incompatible with POST.
            // To work around this limitation, the OpenID Connect request is automatically saved in the cache and will be
            // restored by the OpenID Connect server middleware after the external authentication process has been completed.
            if (!User.Identities.Any(identity => identity.IsAuthenticated)) {
                return new ChallengeResult(new AuthenticationProperties {
                    RedirectUri = Url.Action(nameof(Authorize), new {
                        unique_id = request.GetUniqueIdentifier()
                    })
                });
            }
            
            // Note: AspNet.Security.OpenIdConnect.Server automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see AuthorizationProvider.cs).
            // In theory, this null check is thus not strictly necessary. That said, a race condition
            // and a null reference exception could appear here if you manually removed the application
            // details from the database after the initial check made by AspNet.Security.OpenIdConnect.Server.
            var application = await GetApplicationAsync(request.ClientId, cancellationToken);
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_client",
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Note: in a real world application, you'd probably prefer creating a specific view model.
            return View("Authorize", Tuple.Create(request, application));
        }

        [Authorize, HttpPost("~/connect/authorize/accept"), ValidateAntiForgeryToken]
        public async Task<IActionResult> Accept(CancellationToken cancellationToken) {
            // Extract the authorization request from the cache, the query string or the request form.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
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
                    claim.WithDestination("id_token")
                         .WithDestination("token");
                }

                identity.AddClaim(claim);
            }

            // Note: AspNet.Security.OpenIdConnect.Server automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see AuthorizationProvider.cs).
            // In theory, this null check is thus not strictly necessary. That said, a race condition
            // and a null reference exception could appear here if you manually removed the application
            // details from the database after the initial check made by AspNet.Security.OpenIdConnect.Server.
            var application = await GetApplicationAsync(request.ClientId, cancellationToken);
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_client",
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Create a new ClaimsIdentity containing the claims associated with the application.
            // Note: setting identity.Actor is not mandatory but can be useful to access
            // the whole delegation chain from the resource server (see ResourceController.cs).
            identity.Actor = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.Actor.AddClaim(ClaimTypes.NameIdentifier, application.ApplicationID);
            identity.Actor.AddClaim(ClaimTypes.Name, application.DisplayName, destination: "id_token token");

            var properties = new AuthenticationProperties();

            // Note: you can change the list of scopes granted
            // to the client application using SetScopes:
            properties.SetScopes(new[] {
                /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                /* email: */ OpenIdConnectConstants.Scopes.Email,
                /* profile: */ OpenIdConnectConstants.Scopes.Profile
            });

            // You can also limit the resources endpoints
            // the access token should be issued for:
            properties.SetResources(new[] {
                "http://localhost:54540/"
            });

            // This call will instruct AspNet.Security.OpenIdConnect.Server to serialize
            // the specified identity to build appropriate tokens (id_token and token).
            // Note: you should always make sure the identities you return contain either
            // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
            // identities always contain the name identifier returned by the external provider.
            // Note: the authenticationScheme parameter must match the value configured in Startup.cs.
            await HttpContext.Authentication.SignInAsync(
                OpenIdConnectServerDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity), properties);

            return new EmptyResult();
        }

        [Authorize, HttpPost("~/connect/authorize/deny"), ValidateAntiForgeryToken]
        public IActionResult Deny(CancellationToken cancellationToken) {
            // Extract the authorization request from the cache, the query string or the request form.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Notify AspNet.Security.OpenIdConnect.Server that the authorization grant has been denied.
            // Note: OpenIdConnectServerHandler will automatically take care of redirecting
            // the user agent to the client application using the appropriate response_mode.
            HttpContext.SetOpenIdConnectResponse(new OpenIdConnectMessage {
                Error = "access_denied",
                ErrorDescription = "The authorization grant has been denied by the resource owner",
                RedirectUri = request.RedirectUri,
                State = request.State
            });

            return new EmptyResult();
        }

        [HttpGet("~/connect/logout")]
        public async Task<ActionResult> Logout() {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let AspNet.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
            // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
            // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
            var identity = await HttpContext.Authentication.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationScheme);

            // Extract the logout request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            return View("Logout", Tuple.Create(request, identity));
        }

        [HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
        public async Task Logout(CancellationToken cancellationToken) {
            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            await HttpContext.Authentication.SignOutAsync("ServerCookie");

            // This call will instruct AspNet.Security.OpenIdConnect.Server to serialize
            // the specified identity to build appropriate tokens (id_token and token).
            // Note: you should always make sure the identities you return contain either
            // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
            // identities always contain the name identifier returned by the external provider.
            await HttpContext.Authentication.SignOutAsync(OpenIdConnectServerDefaults.AuthenticationScheme);
        }
        
        protected virtual Task<Application> GetApplicationAsync(string identifier, CancellationToken cancellationToken) {
            // Retrieve the application details corresponding to the requested client_id.
            return (from application in database.Applications
                    where application.ApplicationID == identifier
                    select application).SingleOrDefaultAsync(cancellationToken);
        }
    }
}