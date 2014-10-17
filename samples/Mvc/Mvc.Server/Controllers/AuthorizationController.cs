using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Mvc.Server.Extensions;
using Mvc.Server.Models;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Mvc.Server.Controllers {
    public class AuthorizationController : Controller {
        [Authorize, HttpGet, Route("~/connect/authorize")]
        public async Task<ActionResult> Authorize(
            [ModelBinder(typeof(OpenIdConnectRequestBinder))] OpenIdConnectMessage request,
            [ModelBinder(typeof(OpenIdConnectResponseBinder))] OpenIdConnectMessage response, CancellationToken cancellationToken) {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            if (response != null) {
                return View("Error", response);
            }

            Application application;
            using (var db = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                application = await (from entity in db.Applications
                                     where entity.ApplicationID == request.ClientId
                                     select entity).SingleOrDefaultAsync(cancellationToken);
            }

            // Note: Owin.Security.OpenIdConnect.Server automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see CustomOpenIdConnectServerProvider.cs).
            // In theory, this null check is thus not strictly necessary. That said, a race condition
            // and a null reference exception could appear here if you manually removed the application
            // details from the database after the initial check made by Owin.Security.OpenIdConnect.Server.
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = "invalid_client",
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Note: in a real world application, you'd probably prefer creating a specific view model.
            return View("Authorize", Tuple.Create(request, application));
        }

        [Authorize, HttpPost]
        [Route("~/connect/authorize")]
        [ValidateAntiForgeryToken]
        public ActionResult Authorize(
            [ModelBinder(typeof(OpenIdConnectRequestBinder))] OpenIdConnectMessage request,
            [ModelBinder(typeof(OpenIdConnectResponseBinder))] OpenIdConnectMessage response) {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
            // In this case, the OpenID Connect request is null and cannot be used.
            // When the user agent can be safely redirected to the client application,
            // OpenIdConnectServerHandler automatically handles the error and MVC is not invoked.
            // You can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
            // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
            if (response != null) {
                return View("Error", response);
            }

            // Note: if the "Authorize" key cannot be found in the request body,
            // that's probably because the user agent denied the authorization.
            // In this case, you MUST either stop processing the request or
            // call OwinContext.SetOpenIdConnectResponse with an error message.
            if (string.IsNullOrWhiteSpace(Request.Form.Get("Authorize"))) {
                // Notify Owin.Security.OpenIdConnect.Server that the authorization grant has been denied.
                // Note: OpenIdConnectServerHandler will automatically take care of redirecting
                // the user agent to the client application using the appropriate response_mode.
                OwinContext.SetOpenIdConnectResponse(new OpenIdConnectMessage {
                    Error = "access_denied",
                    ErrorDescription = "The authorization grant has been denied by the resource owner",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });

                return new HttpStatusCodeResult(200);
            }

            // Create a new ClaimsIdentity containing the claims retrieved from the external
            // identity provider (e.g Google, Facebook, a WS-Fed provider or another OIDC server).
            // Note: the authenticationType parameter must match the value configured in Startup.cs.
            var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationType);

            foreach (var claim in OwinContext.Authentication.User.Claims) {
                // Allow both ClaimTypes.Name and ClaimTypes.NameIdentifier to be added in the id_token.
                // The other claims won't be visible for the client application.
                if (claim.Type == ClaimTypes.Name || claim.Type == ClaimTypes.NameIdentifier) {
                    claim.Properties.Add("destination", "id_token token");
                }

                identity.AddClaim(claim);
            }

            // This call will instruct Owin.Security.OpenIdConnect.Server to serialize
            // the specified identity to build appropriate tokens (id_token and token).
            // Note: you should always make sure the identities you return contain either
            // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
            // identities always contain the name identifier returned by the external provider.
            OwinContext.Authentication.SignIn(identity);

            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            // Note: this call requires the user agent to re-authenticate each time
            // an authorization is granted to a client application. You can safely
            // remove it and use the signout endpoint from AuthenticationModule.cs instead.
            OwinContext.Authentication.SignOut("ServerCookie");

            return new HttpStatusCodeResult(200);
        }

        /// <summary>
        /// Gets the IOwinContext instance associated with the current request.
        /// </summary>
        protected IOwinContext OwinContext {
            get {
                IOwinContext context = HttpContext.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from HttpContext");
                }

                return context;
            }
        }
    }
}