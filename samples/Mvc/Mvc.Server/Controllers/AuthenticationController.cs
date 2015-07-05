using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc;
using Mvc.Server.Extensions;
using Mvc.Server.Models;

namespace Mvc.Server.Controllers {
    public class AuthenticationController : Controller {
        [HttpGet("~/signin")]
        public ActionResult SignIn(string returnUrl = null) {
            // Note: the "returnUrl" parameter corresponds to the endpoint the user agent
            // will be redirected to after a successful authentication and not
            // the redirect_uri of the requesting client application.
            ViewBag.ReturnUrl = returnUrl;

            // Note: in a real world application, you'd probably prefer creating a specific view model.
            return View("SignIn", new AuthenticationModel() {AuthenticationDescriptions = Context.GetExternalProviders()});
        }

        [HttpPost("~/signin")]
        public ActionResult SignIn(AuthenticationModel  model) {

            if (!string.IsNullOrWhiteSpace(model.Username) && model.Username == model.Password)
            {
                var properties = new AuthenticationProperties
                {
                    RedirectUri = model.ReturnUrl
                };

                var identity = new ClaimsIdentity("ServerCookie");
                identity.AddClaim(new Claim(ClaimTypes.Name, model.Username));
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, model.Username));

                var principal = new ClaimsPrincipal(identity);

                Context.Authentication.SignInAsync("ServerCookie", principal, properties);
                return new EmptyResult();
            }
            


            // Note: the "provider" parameter corresponds to the external
            // authentication provider choosen by the user agent.
            if (string.IsNullOrEmpty(model.Provider)) {
                return HttpBadRequest();
            }

            if (!Context.IsProviderSupported(model.Provider)) {
                return HttpBadRequest();
            }

            // Note: the "returnUrl" parameter corresponds to the endpoint the user agent
            // will be redirected to after a successful authentication and not
            // the redirect_uri of the requesting client application.
            if (string.IsNullOrEmpty(model.ReturnUrl)) {
                return HttpBadRequest();
            }

            // Instruct the middleware corresponding to the requested external identity
            // provider to redirect the user agent to its own authorization endpoint.
            // Note: the authenticationScheme parameter must match the value configured in Startup.cs
            return new ChallengeResult(model.Provider, new AuthenticationProperties {
                RedirectUri = model.ReturnUrl
            });
        }

        [HttpGet("~/signout"), HttpPost("~/signout")]
        public async Task SignOut() {
            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).

            await Context.Authentication.SignOutAsync("ServerCookie");
        }
    }
}