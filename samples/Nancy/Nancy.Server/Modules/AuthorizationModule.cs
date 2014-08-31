using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Nancy.Security;
using Nancy.Server.Extensions;
using Nancy.Server.Models;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server.Modules {
    public class AuthorizationModule : NancyModule {
        public AuthorizationModule() {
            Get["/connect/authorize", runAsync: true] = async (parameters, cancellationToken) => {
                this.RequiresMSOwinAuthentication();
                this.CreateNewCsrfToken();

                IOwinContext context = Context.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                // Extract the error details from the OWIN environment to display them in the Razor view.
                // Note: you can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
                // handle the error by switching ApplicationCanDisplayErrors to false in Startup.cs
                string error, errorDescription, errorUri;
                error = context.GetOpenIdConnectRequestError(out errorDescription, out errorUri);

                if (!string.IsNullOrWhiteSpace(error)) {
                    // Note: in a real world application, you'd probably prefer creating a specific view model.
                    return View["error.cshtml", Tuple.Create(error, errorDescription, errorUri)];
                }

                // Extract the authorization request from the OWIN environment.
                OpenIdConnectMessage request = context.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["error.cshtml", Tuple.Create(
                        /* error: */ "invalid_request",
                        /* errorDescription: */ "An internal error has occurred",
                        /* errorUri: */ string.Empty)];
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
                    return View["error.cshtml", Tuple.Create(
                        /* error: */ "invalid_client",
                        /* errorDescription: */ "Details concerning the calling client application cannot be found in the database",
                        /* errorUri: */ string.Empty)];
                }

                // Note: in a real world application, you'd probably prefer creating a specific view model.
                return View["authorize.cshtml", Tuple.Create(request, application)];
            };

            Post["/connect/authorize"] = parameters => {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                // Create a new ClaimsIdentity containing the claims retrieved from the external
                // identity provider (e.g Google, Facebook, a WS-Fed provider or another OIDC server).
                // Note: the authenticationType parameter must match the value configured in Startup.cs.
                var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationType);

                // Note: in a real world implementation, you'd likely filter
                // the claims added to "identity" to avoid leaking too many
                // information to the final client application.
                identity.AddClaims(manager.User.Claims);

                // This call will instruct Owin.Security.OpenIdConnect.Server to serialize
                // the specified identity to build appropriate tokens (id_token and token).
                manager.SignIn(identity);

                // Instruct the cookies middleware to delete the local cookie created
                // when the user agent is redirect from the external identity provider
                // after a successful authentication flow (e.g Google or Facebook).
                // Note: this call requires the user agent to re-authenticate each time
                // an authorization is granted to a client application. You can safely
                // remove it and use the signout endpoint from AuthenticationModule.cs instead.
                manager.SignOut("ServerCookie");

                return HttpStatusCode.OK;
            };
        }
    }
}