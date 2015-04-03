using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
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

                // Note: when a fatal error occurs during the request processing, an OpenID Connect response
                // is prematurely forged and added to the OWIN context by OpenIdConnectServerHandler.
                // When the user agent can be safely redirected to the client application,
                // OpenIdConnectServerHandler automatically handles the error and Nancy is not invoked.
                // You can safely remove this part and let Owin.Security.OpenIdConnect.Server automatically
                // handle the unrecoverable errors by switching ApplicationCanDisplayErrors to false in Startup.cs
                OpenIdConnectMessage response = OwinContext.GetOpenIdConnectResponse();
                if (response != null) {
                    return View["error.cshtml", response];
                }

                // Extract the authorization request from the OWIN environment.
                OpenIdConnectMessage request = OwinContext.GetOpenIdConnectRequest();
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

                // Create a new ClaimsIdentity containing the claims retrieved from the external
                // identity provider (e.g Google, Facebook, a WS-Fed provider or another OIDC server).
                // Note: the authenticationType parameter must match the value configured in Startup.cs.
                var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationType);

                foreach (var claim in OwinContext.Authentication.User.Claims) {
                    // Allow ClaimTypes.Name to be added in the id_token.
                    // ClaimTypes.NameIdentifier is automatically added, even if its
                    // destination is not defined or doesn't include "id_token".
                    // The other claims won't be visible for the client application.
                    if (claim.Type == ClaimTypes.Name) {
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

                return HttpStatusCode.OK;
            };

            Post["/connect/authorize", condition: context => context.Request.Form.Deny] = parameters => {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                // Extract the authorization request from the OWIN environment.
                OpenIdConnectMessage request = OwinContext.GetOpenIdConnectRequest();
                if (request == null) {
                    return View["error.cshtml", new OpenIdConnectMessage {
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
                    RedirectUri = request.RedirectUri, State = request.State
                });

                return HttpStatusCode.OK;
            };
        }

        /// <summary>
        /// Gets the IOwinContext instance associated with the current request.
        /// </summary>
        protected IOwinContext OwinContext {
            get {
                IOwinContext context = Context.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                return context;
            }
        }
    }
}