using System;
using Microsoft.Owin.Security;
using Nancy.Security;
using Nancy.Server.Extensions;

namespace Nancy.Server.Modules {
    public class AuthenticationModule : NancyModule {
        public AuthenticationModule() {
            Get["/signin"] = parameters => {
                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                ViewBag.ReturnUrl = (string) Request.Query.ReturnUrl;
                return View["signin.cshtml", manager.GetExternalProviders()];
            };

            Post["/signin"] = parameters => {
                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                var provider = (string) Request.Form.Provider;
                if (string.IsNullOrWhiteSpace(provider)) {
                    return HttpStatusCode.BadRequest;
                }

                if (!manager.IsProviderSupported(provider)) {
                    return HttpStatusCode.BadRequest;
                }

                var returnUrl = (string) Request.Form.ReturnUrl;
                if (string.IsNullOrWhiteSpace(returnUrl)) {
                    returnUrl = "/";
                }

                var properties = new AuthenticationProperties {
                    RedirectUri = returnUrl
                };

                manager.Challenge(properties, provider);

                return HttpStatusCode.Unauthorized;
            };

            Get["/signout"] = Post["/signout"] = parameters => {
                IAuthenticationManager manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    throw new NotSupportedException("An OWIN authentication manager cannot be extracted from NancyContext");
                }

                manager.SignOut("ExternalCookie");

                return HttpStatusCode.OK;
            };
        }
    }
}