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
            // Owin.Security.OpenIdConnect.Server supports authorization requests received either via GET or POST.
            // You're strongly encouraged to support both methods to make your app specs-compliant.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            Get["/connect/authorize", runAsync: true] =
            Post["/connect/authorize", runAsync: true,
                condition: context => !context.Request.Form.Authorize &&
                                      !context.Request.Form.Deny] = async (parameters, cancellationToken) => {
                this.RequiresMSOwinAuthentication();
                this.CreateNewCsrfToken();

                IOwinContext context = Context.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                // Note: when a fatal error occurs during the request processing, an OpenID Connect response
                // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
                // When the user agent can be safely redirected to the client application,
                // OpenIdConnectServerHandler automatically handles the error and Nancy is not invoked.
                // You can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
                // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
                OpenIdConnectMessage response = context.GetOpenIdConnectResponse();
                if (response != null) {
                    return View["error.cshtml", response];
                }

                // Extract the authorization request from the OWIN environment.
                OpenIdConnectMessage request = context.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_request",
                        ErrorDescription = "An internal error has occurred"
                    }];
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
                    return View["error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_client",
                        ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                    }];
                }

                // Note: in a real world application, you'd probably prefer creating a specific view model.
                return View["authorize.cshtml", Tuple.Create(request, application)];
            };

            Post["/connect/authorize", condition: context => context.Request.Form.Authorize] = parameters => {
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
                // Note: you should always make sure the identities you return contain either
                // a 'sub' or a 'ClaimTypes.NameIdentifier' claim. In this case, the returned
                // identities always contain the name identifier returned by the external provider.
                manager.SignIn(identity);

                // Instruct the cookies middleware to delete the local cookie created
                // when the user agent is redirected from the external identity provider
                // after a successful authentication flow (e.g Google or Facebook).
                // Note: this call requires the user agent to re-authenticate each time
                // an authorization is granted to a client application. You can safely
                // remove it and use the signout endpoint from AuthenticationModule.cs instead.
                manager.SignOut("ServerCookie");

                return HttpStatusCode.OK;
            };

            Post["/connect/authorize", condition: context => context.Request.Form.Deny] = parameters => {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                IOwinContext context = Context.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                // Extract the authorization request from the OWIN environment.
                OpenIdConnectMessage request = context.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["error.cshtml", new OpenIdConnectMessage {
                        Error = "invalid_request",
                        ErrorDescription = "An internal error has occurred"
                    }];
                }

                // Notify Owin.Security.OpenIdConnect.Server that the authorization grant has been denied.
                // Note: OpenIdConnectServerHandler will automatically take care of redirecting
                // the user agent to the client application using the appropriate response_mode.
                context.SetOpenIdConnectResponse(new OpenIdConnectMessage {
                    Error = "access_denied",
                    ErrorDescription = "The authorization grant has been denied by the resource owner",
                    RedirectUri = request.RedirectUri, State = request.State
                });

                return HttpStatusCode.OK;
            };
        }
    }
}