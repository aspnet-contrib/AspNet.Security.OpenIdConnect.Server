using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Mvc.Server.Helpers;
using Mvc.Server.Models;

namespace Mvc.Server.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly ApplicationContext _database;

        public AuthorizationController(ApplicationContext database)
        {
            _database = database;
        }

        [Authorize, HttpGet("~/connect/authorize")]
        public async Task<IActionResult> Authorize(CancellationToken cancellationToken)
        {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
            // You can safely remove this part and let ASOS automatically handle the unrecoverable errors
            // by switching ApplicationCanDisplayErrors to false in Startup.cs.
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return View("Error", response);
            }

            // Extract the authorization request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return View("Error", new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred."
                });
            }

            // Note: ASOS automatically ensures that an application corresponds to the client_id specified
            // in the authorization request by calling OpenIdConnectServerProvider.ValidateAuthorizationRequest.
            // In theory, this null check shouldn't be needed, but a race condition could occur if you
            // manually removed the application details from the database after the initial check made by ASOS.
            var application = await GetApplicationAsync(request.ClientId, cancellationToken);
            if (application == null)
            {
                return View("Error", new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "The specified client identifier is invalid."
                });
            }

            // Note: in a real world application, you'd probably prefer creating a specific view model.
            return View("Authorize", Tuple.Create(request, application));
        }

        [Authorize, FormValueRequired("submit.Accept")]
        [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
        public async Task<IActionResult> Accept(CancellationToken cancellationToken)
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return View("Error", response);
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return View("Error", new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred."
                });
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(
                OpenIdConnectServerDefaults.AuthenticationScheme,
                OpenIdConnectConstants.Claims.Name,
                OpenIdConnectConstants.Claims.Role);

            // Note: the "sub" claim is mandatory and an exception is thrown if this claim is missing.
            identity.AddClaim(
                new Claim(OpenIdConnectConstants.Claims.Subject, User.FindFirst(ClaimTypes.NameIdentifier).Value)
                    .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken,
                                     OpenIdConnectConstants.Destinations.IdentityToken));

            identity.AddClaim(
                new Claim(OpenIdConnectConstants.Claims.Name, User.FindFirst(ClaimTypes.Name).Value)
                    .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken,
                                     OpenIdConnectConstants.Destinations.IdentityToken));

            var application = await GetApplicationAsync(request.ClientId, cancellationToken);
            if (application == null)
            {
                return View("Error", new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "The specified client identifier is invalid."
                });
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

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

            // Returning a SignInResult will ask ASOS to serialize the specified identity to build appropriate tokens.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        [Authorize, FormValueRequired("submit.Deny")]
        [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
        public IActionResult Deny(CancellationToken cancellationToken)
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return View("Error", response);
            }

            // Notify ASOS that the authorization grant has been denied by the resource owner.
            // Note: OpenIdConnectServerHandler will automatically take care of redirecting
            // the user agent to the client application using the appropriate response_mode.
            return Challenge(OpenIdConnectServerDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/logout")]
        public async Task<ActionResult> Logout(CancellationToken cancellationToken)
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return View("Error", response);
            }

            // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
            // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
            // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
            var result = await HttpContext.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationScheme);

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return View("Error", new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred."
                });
            }

            return View("Logout", Tuple.Create(request, result?.Principal));
        }

        [HttpPost("~/connect/logout")]
        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            // Returning a SignOutResult will ask the cookies middleware to delete the local cookie created when
            // the user agent is redirected from the external identity provider after a successful authentication flow
            // and will redirect the user agent to the post_logout_redirect_uri specified by the client application.
            return SignOut("ServerCookie", OpenIdConnectServerDefaults.AuthenticationScheme);
        }

        protected virtual Task<Application> GetApplicationAsync(string identifier, CancellationToken cancellationToken)
        {
            // Retrieve the application details corresponding to the requested client_id.
            return (from application in _database.Applications
                    where application.ApplicationID == identifier
                    select application).SingleOrDefaultAsync(cancellationToken);
        }
    }
}
