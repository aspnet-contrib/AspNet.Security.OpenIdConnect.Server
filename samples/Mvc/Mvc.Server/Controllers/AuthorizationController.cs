using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Mvc;
using Microsoft.Data.Entity;
using Microsoft.IdentityModel.Protocols;
using Mvc.Server.Models;

namespace Mvc.Server.Controllers {
    public class AuthorizationController : Controller {
        private readonly ApplicationContext database;

        public AuthorizationController(ApplicationContext database) {
            this.database = database;
        }

        [Authorize, HttpGet("~/connect/authorize")]
        public async Task<IActionResult> Authorize(CancellationToken cancellationToken) {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let AspNet.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // Extract the authorization request from the OWIN environment.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Note: AspNet.Security.OpenIdConnect.Server automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see CustomOpenIdConnectServerProvider.cs).
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

        [Authorize, HttpPost("~/connect/authorize")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Authorize([FromForm] string authorize, CancellationToken cancellationToken) {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let AspNet.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // Extract the authorization request from the OWIN environment.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Note: if the "Authorize" key cannot be found in the request form,
            // that's probably because the user agent denied the authorization.
            // In this case, you MUST either stop processing the request or
            // call OwinContext.SetOpenIdConnectResponse with an error message.
            if (string.IsNullOrWhiteSpace(authorize)) {
                // Notify AspNet.Security.OpenIdConnect.Server that the authorization grant has been denied.
                // Note: OpenIdConnectServerHandler will automatically take care of redirecting
                // the user agent to the client application using the appropriate response_mode.
                Context.SetOpenIdConnectResponse(new OpenIdConnectMessage {
                    Error = "access_denied",
                    ErrorDescription = "The authorization grant has been denied by the resource owner",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });

                return new HttpStatusCodeResult(200);
            }

            // Create a new ClaimsIdentity containing the claims retrieved from the external
            // identity provider (e.g Google, Facebook, a WS-Fed provider or another OIDC server).
            var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationScheme);

            foreach (var claim in Context.User.Claims) {
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
            
            // Note: Owin.Security.OpenIdConnect.Server automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see AuthorizationProvider.cs).
            // In theory, this null check is thus not strictly necessary. That said, a race condition
            // and a null reference exception could appear here if you manually removed the application
            // details from the database after the initial check made by Owin.Security.OpenIdConnect.Server.
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
            identity.Actor = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationScheme);
            identity.Actor.AddClaim(ClaimTypes.NameIdentifier, application.ApplicationID);
            identity.Actor.AddClaim(ClaimTypes.Name, application.DisplayName, destination: "id_token token");

            // This call will instruct AspNet.Security.OpenIdConnect.Server to serialize
            // the specified identity to build appropriate tokens (id_token and token).
            // Note: you should always make sure the identities you return contain either
            // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
            // identities always contain the name identifier returned by the external provider.
            // Note: the authenticationScheme parameter must match the value configured in Startup.cs.
            Context.Authentication.SignIn(OpenIdConnectDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            return new HttpStatusCodeResult(200);
        }

        [HttpGet, Route("~/connect/logout")]
        public async Task<ActionResult> Logout() {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
            // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
            // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
            var identity = await Context.Authentication.AuthenticateAsync(OpenIdConnectDefaults.AuthenticationScheme);

            // Extract the logout request from the OWIN environment.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            return View("Logout", Tuple.Create(request, identity));
        }

        [HttpPost, Route("~/connect/logout")]
        [ValidateAntiForgeryToken]
        public ActionResult Logout(CancellationToken cancellationToken) {
            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            Context.Authentication.SignOut("ServerCookie");

            // This call will instruct Owin.Security.OpenIdConnect.Server to serialize
            // the specified identity to build appropriate tokens (id_token and token).
            // Note: you should always make sure the identities you return contain either
            // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
            // identities always contain the name identifier returned by the external provider.
            Context.Authentication.SignOut(OpenIdConnectDefaults.AuthenticationScheme);

            return new HttpStatusCodeResult(200);
        }

        protected async Task<Application> GetApplicationAsync(string identifier, CancellationToken cancellationToken) {
            // Retrieve the application details corresponding to the requested client_id.
            return await (from application in database.Applications
                          where application.ApplicationID == identifier
                          select application).SingleOrDefaultAsync(cancellationToken);
        }
    }
}