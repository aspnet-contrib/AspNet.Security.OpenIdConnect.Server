using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Http.Authentication;
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
        
        [HttpGet("~/connect/authorize", Order = 1)]
        [HttpPost("~/connect/authorize", Order = 1)]
        public async Task<IActionResult> Authorize(CancellationToken cancellationToken) {
            // Note: this action is bound to the AuthorizationEndpointPath defined in Startup.cs
            // (by default "/connect/authorize" if you don't specify an explicit path).
            // When an OpenID Connect request arrives, it is automatically inspected by
            // OpenIdConnectServerHandler before this action is executed by ASP.NET MVC.
            // It is the only endpoint the OpenID Connect request can be extracted from.
            // For the rest of the authorization process, it will be stored in the user's session and retrieved
            // using "Context.Session.GetOpenIdConnectRequest" instead of "Context.GetOpenIdConnectRequest",
            // that would otherwise extract the OpenID Connect request from the query string or from the request body.

            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let AspNet.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // Extract the authorization request from the ASP.NET request.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Generate a unique 16-bytes identifier and save
            // the OpenID Connect request in the user's session.
            var key = GenerateKey();
            Context.Session.SetOpenIdConnectRequest(key, request);

            // Note: authentication could be theorically enforced at the filter level via AuthorizeAttribute
            // but this authorization endpoint accepts both GET and POST requests while the cookie middleware
            // only uses 302 responses to redirect the user agent to the login page, making it incompatible with POST.
            // To work around this limitation, the OpenID Connect request is saved in the user's session and will
            // be restored in the other "Authorize" method, after the authentication process has been completed.
            if (User.Identity == null || !User.Identity.IsAuthenticated) {
                return new ChallengeResult(new AuthenticationProperties {
                    RedirectUri = Url.Action(nameof(Authorize), new { key })
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
            return View("Authorize", Tuple.Create(request, application, key));
        }

        [Authorize, HttpGet("~/connect/authorize/{key}", Order = 0)]
        public async Task<IActionResult> Authorize([FromRoute] string key, CancellationToken cancellationToken) {
            // Extract the OpenID Connect request stored in the user's session.
            var request = Context.Session.GetOpenIdConnectRequest(key);
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
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
            return View("Authorize", Tuple.Create(request, application, key));
        }

        [Authorize, HttpPost("~/connect/authorize/accept/{key}"), ValidateAntiForgeryToken]
        public async Task<IActionResult> Accept([FromRoute] string key, CancellationToken cancellationToken) {
            // Extract the OpenID Connect request stored in the user's session.
            var request = Context.Session.GetOpenIdConnectRequest(key);
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Restore the OpenID Connect request in the ASP.NET context
            // so AspNet.Security.OpenIdConnect.Server can retrieve it.
            Context.SetOpenIdConnectRequest(request);

            // Remove the OpenID Connect request stored in the user's session.
            Context.Session.SetOpenIdConnectRequest(key, null);

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationScheme);

            // Copy the claims retrieved from the external identity provider
            // (e.g Google, Facebook, a WS-Fed provider or another OIDC server).
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

        [Authorize, HttpPost("~/connect/authorize/deny/{key}"), ValidateAntiForgeryToken]
        public IActionResult Deny([FromRoute] string key, CancellationToken cancellationToken) {
            // Extract the OpenID Connect request stored in the user's session.
            var request = Context.Session.GetOpenIdConnectRequest(key);
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Restore the OpenID Connect request in the ASP.NET context
            // so AspNet.Security.OpenIdConnect.Server can retrieve it.
            Context.SetOpenIdConnectRequest(request);

            // Remove the OpenID Connect request stored in the user's session.
            Context.Session.SetOpenIdConnectRequest(key, null);

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

        [HttpGet("~/connect/logout")]
        public async Task<ActionResult> Logout() {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let AspNet.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
            // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
            // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
            var identity = await Context.Authentication.AuthenticateAsync(OpenIdConnectDefaults.AuthenticationScheme);

            // Extract the logout request from the ASP.NET environment.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_request",
                    ErrorDescription = "An internal error has occurred"
                });
            }

            return View("Logout", Tuple.Create(request, identity));
        }

        [HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
        public ActionResult Logout(CancellationToken cancellationToken) {
            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            Context.Authentication.SignOut("ServerCookie");

            // This call will instruct AspNet.Security.OpenIdConnect.Server to serialize
            // the specified identity to build appropriate tokens (id_token and token).
            // Note: you should always make sure the identities you return contain either
            // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
            // identities always contain the name identifier returned by the external provider.
            Context.Authentication.SignOut(OpenIdConnectDefaults.AuthenticationScheme);

            return new HttpStatusCodeResult(200);
        }
        
        protected virtual Task<Application> GetApplicationAsync(string identifier, CancellationToken cancellationToken) {
            // Retrieve the application details corresponding to the requested client_id.
            return (from application in database.Applications
                    where application.ApplicationID == identifier
                    select application).SingleOrDefaultAsync(cancellationToken);
        }

        protected virtual string GenerateKey() {
            using (var generator = RandomNumberGenerator.Create()) {
                var buffer = new byte[16];
                generator.GetBytes(buffer);

                return new Guid(buffer).ToString();
            }
        }
    }
}