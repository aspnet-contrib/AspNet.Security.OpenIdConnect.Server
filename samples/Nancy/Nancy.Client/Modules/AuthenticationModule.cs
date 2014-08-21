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

                manager.Challenge(properties, OpenIdConnectAuthenticationDefaults.AuthenticationType);

                return HttpStatusCode.Unauthorized;
            };

            Get["/signout"] = Post["/signout"] = parameters => {
                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                manager.SignOut("ExternalCookie");

                return Response.AsRedirect("/");
            };
        }
    }
}