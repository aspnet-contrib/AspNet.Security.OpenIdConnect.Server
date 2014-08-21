using System;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Nancy.Security;

namespace Nancy.Client.Modules {
    public class AuthenticationModule : NancyModule {
        public AuthenticationModule() {
            Get["/signin"] = parameters => {
                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                var properties = new AuthenticationProperties {
                    RedirectUri = "/"
                };

                // Instruct the OIDC client middleware to redirect the user agent to the identity provider.
                // Note: the authenticationType parameter must match the value configured in Startup.cs
                manager.Challenge(properties, OpenIdConnectAuthenticationDefaults.AuthenticationType);

                return HttpStatusCode.Unauthorized;
            };

            Get["/signout"] = Post["/signout"] = parameters => {
                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                // Instruct the cookies middleware to delete the local cookie created when the user agent
                // is redirect from the identity provider after a successful authorization flow.
                // Note: this call doesn't disconnect the user agent at the identity provider level (yet).
                manager.SignOut("ClientCookie");

                return Response.AsRedirect("/");
            };
        }
    }
}