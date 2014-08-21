using System;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Nancy.Security;
using Nancy.Server.Extensions;
using Owin;
using Owin.Security.OpenIdConnect.Server;
using Owin.Security.OpenIdConnect.Server.Messages;

namespace Nancy.Server.Modules {
    public class AuthorizationModule : NancyModule {
        public AuthorizationModule() {
            Get["/oauth2/authorize"] = parameters => {
                this.RequiresMSOwinAuthentication();
                this.CreateNewCsrfToken();

                IOwinContext context = Context.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                string error, errorDescription, errorUri;
                error = context.GetAuthorizeRequestError(out errorDescription, out errorUri);

                if (!string.IsNullOrWhiteSpace(error)) {
                    return View["error.cshtml", Tuple.Create(error, errorDescription, errorUri)];
                }

                AuthorizeEndpointRequest request = context.GetAuthorizeEndpointRequest();
                if (request == null) {
                    return HttpStatusCode.BadRequest;
                }

                return View["authorize.cshtml", request];
            };

            Post["/oauth2/authorize"] = parameters => {
                this.RequiresMSOwinAuthentication();
                this.ValidateCsrfToken();

                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationType);
                identity.AddClaims(manager.User.Claims);

                manager.SignIn(identity);
                manager.SignOut("InternalCookie");

                return HttpStatusCode.OK;
            };
        }
    }
}