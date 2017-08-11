using System;
using System.Security.Claims;
using Microsoft.Owin.Security;
using Nancy.Security;
using Nancy.Server.Extensions;

namespace Nancy.Server.Modules
{
    public class AuthenticationModule : NancyModule
    {
        public AuthenticationModule()
        {
            Get["/signin"] = parameters =>
            {
                this.CreateNewCsrfToken();

                // Note: the ReturnUrl parameter corresponds to the endpoint the user agent
                // will be redirected to after a successful authentication and not
                // the redirect_uri of the requesting client application.
                return View["SignIn.cshtml", (string) Request.Query.ReturnUrl];
            };

            Post["/signin"] = parameters =>
            {
                this.ValidateCsrfToken();

                var identifier = (string) Request.Form.Identifier;
                if (string.IsNullOrEmpty(identifier))
                {
                    return HttpStatusCode.BadRequest;
                }

                // Note: the ReturnUrl parameter corresponds to the endpoint the user agent
                // will be redirected to after a successful authentication and not
                // the redirect_uri of the requesting client application.
                var returnUrl = (string) Request.Form.ReturnUrl;
                if (string.IsNullOrEmpty(returnUrl))
                {
                    return HttpStatusCode.BadRequest;
                }

                var properties = new AuthenticationProperties
                {
                    RedirectUri = returnUrl
                };

                var identity = new ClaimsIdentity("ServerCookie");
                identity.AddClaim(new Claim(ClaimTypes.Name, identifier));
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, identifier));

                AuthenticationManager.SignIn(properties, identity);

                return Response.AsRedirect(returnUrl);
            };

            Get["/signout"] = Post["/signout"] = parameters =>
            {
                AuthenticationManager.SignOut("ServerCookie");

                return HttpStatusCode.OK;
            };
        }

        /// <summary>
        /// Gets the IAuthenticationManager instance associated with the current request.
        /// </summary>
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                var context = Context.GetOwinContext();
                if (context == null)
                {
                    throw new NotSupportedException("An OWIN context cannot be extracted from NancyContext");
                }

                return context.Authentication;
            }
        }
    }
}
