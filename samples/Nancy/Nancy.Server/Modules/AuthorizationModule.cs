using System;
using System.Linq;
using System.Security.Claims;
using System.Data.Entity;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Nancy.Security;
using Nancy.Server.Extensions;
using Nancy.Server.Models;
using Owin;
using Owin.Security.OpenIdConnect.Server;
using Owin.Security.OpenIdConnect.Server.Messages;

namespace Nancy.Server.Modules {
    public class AuthorizationModule : NancyModule {
        public AuthorizationModule() {
            Get["/oauth2/authorize", runAsync: true] = async (parameters, cancellationToken) => {
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
                    return View["error.cshtml", Tuple.Create(
                        /* error: */ "invalid_request",
                        /* errorDescription: */ "An internal error has occurred",
                        /* errorUri: */ string.Empty)];
                }

                Application application;
                using (var db = new ApplicationContext()) {
                    application = await (from entity in db.Applications
                                         where entity.ApplicationID == request.ClientId
                                         select entity).SingleOrDefaultAsync(cancellationToken);
                }

                if (application == null) {
                    return View["error.cshtml", Tuple.Create(
                        /* error: */ "invalid_client",
                        /* errorDescription: */ "Details concerning the calling client application cannot be found in the database",
                        /* errorUri: */ string.Empty)];
                }

                return View["authorize.cshtml", Tuple.Create(request, application)];
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