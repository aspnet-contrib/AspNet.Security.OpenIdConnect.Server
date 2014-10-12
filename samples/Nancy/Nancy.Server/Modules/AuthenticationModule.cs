using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Nancy.Server.Extensions;

namespace Nancy.Server.Modules {
    public class AuthenticationModule : NancyModule {
        public AuthenticationModule() {
            Get["/signin"] = parameters => {
                // Note: the ReturnUrl parameter corresponds to the endpoint the user agent
                // will be redirected to after a successful authentication and not
                // the redirect_uri of the requesting client application.
                ViewBag.ReturnUrl = (string) Request.Query.ReturnUrl;

                // Note: in a real world application, you'd probably prefer creating a specific view model.
                return View["signin.cshtml", AuthenticationManager.GetExternalProviders()];
            };

            Post["/signin"] = parameters => {
                // Note: the Provider parameters corresponds to the external
                // authentication provider choosen by the user agent.
                var provider = (string) Request.Form.Provider;
                if (string.IsNullOrWhiteSpace(provider)) {
                    return HttpStatusCode.BadRequest;
                }

                if (!AuthenticationManager.IsProviderSupported(provider)) {
                    return HttpStatusCode.BadRequest;
                }

                // Note: the ReturnUrl parameter corresponds to the endpoint the user agent
                // will be redirected to after a successful authentication and not
                // the redirect_uri of the requesting client application.
                var returnUrl = (string) Request.Form.ReturnUrl;
                if (string.IsNullOrWhiteSpace(returnUrl)) {
                    return HttpStatusCode.BadRequest;
                }

                var properties = new AuthenticationProperties {
                    RedirectUri = returnUrl
                };

                // Instruct the middleware corresponding to the requested external identity
                // provider to redirect the user agent to its own authorization endpoint.
                // Note: the authenticationType parameter must match the value configured in Startup.cs
                AuthenticationManager.Challenge(properties, provider);

                return HttpStatusCode.Unauthorized;
            };

            Get["/signout"] = Post["/signout"] = parameters => {
                // Instruct the cookies middleware to delete the local cookie created
                // when the user agent is redirected from the external identity provider
                // after a successful authentication flow (e.g Google or Facebook).
                AuthenticationManager.SignOut("ServerCookie");

                return HttpStatusCode.OK;
            };
        }

        /// <summary>
        /// Gets the IAuthenticationManager instance associated with the current request.
        /// </summary>
        protected IAuthenticationManager AuthenticationManager {
            get {
                IOwinContext context = Context.GetOwinContext();
                if (context == null) {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                return context.Authentication;
            }
        }
    }
}