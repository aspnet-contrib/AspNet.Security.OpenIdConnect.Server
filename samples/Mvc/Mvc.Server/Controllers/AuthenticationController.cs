using System;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Mvc.Server.Extensions;

namespace Mvc.Server.Controllers {
    public class AuthenticationController : Controller {
        [HttpGet, Route("~/signin")]
        public ActionResult SignIn(string returnUrl = null) {
            // Note: the ReturnUrl parameter corresponds to the endpoint the user agent
            // will be redirected to after a successful authentication and not
            // the redirect_uri of the requesting client application.
            ViewBag.ReturnUrl = returnUrl;

            // Note: in a real world application, you'd probably prefer creating a specific view model.
            return View("SignIn", OwinContext.Authentication.GetExternalProviders());
        }

        [HttpPost, Route("~/signin")]
        public ActionResult SignIn(string provider, string returnUrl) {
            // Note: the Provider parameters corresponds to the external
            // authentication provider choosen by the user agent.
            if (string.IsNullOrWhiteSpace(provider)) {
                return new HttpStatusCodeResult(400);
            }

            if (!OwinContext.Authentication.IsProviderSupported(provider)) {
                return new HttpStatusCodeResult(400);
            }

            // Note: the ReturnUrl parameter corresponds to the endpoint the user agent
            // will be redirected to after a successful authentication and not
            // the redirect_uri of the requesting client application.
            if (string.IsNullOrWhiteSpace(returnUrl)) {
                return new HttpStatusCodeResult(400);
            }

            var properties = new AuthenticationProperties {
                RedirectUri = returnUrl
            };

            // Instruct the middleware corresponding to the requested external identity
            // provider to redirect the user agent to its own authorization endpoint.
            // Note: the authenticationType parameter must match the value configured in Startup.cs
            OwinContext.Authentication.Challenge(properties, provider);

            return new HttpStatusCodeResult(401);
        }

        [AcceptVerbs(HttpVerbs.Get | HttpVerbs.Post), Route("~/signout")]
        public ActionResult SignOut() {
            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
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