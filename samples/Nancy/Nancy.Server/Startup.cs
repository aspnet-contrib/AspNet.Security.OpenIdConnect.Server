using System;
using System.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Nancy.Owin;
using Nancy.Server.Providers;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            var key = new InMemorySymmetricSecurityKey(Convert.FromBase64String("Srtjyi8wMFfmP9Ub8U2ieVGAcrP/7gK3VM/K6KfJ/fI="));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

            app.SetDefaultSignInAsAuthenticationType("InternalCookie");

            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "InternalCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "InternalCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
                LoginPath = new PathString("/signin")
            });

            app.UseGoogleAuthentication();

            app.UseOpenIdConnectServer(new OpenIdConnectServerOptions {
                AuthenticationType = OpenIdConnectDefaults.AuthenticationType,
                IdTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                IssuerName = "urn:authServer",
                SigningCredentials = credentials,
                TokenEndpointPath = new PathString("/oauth2/access_token"),
                AuthorizeEndpointPath = new PathString("/oauth2/authorize"),
                Provider = new CustomOpenIdConnectServerProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true,
                ApplicationCanDisplayErrors = true,
                AuthorizationCodeProvider = new TestAuthenticationTokenProvider(),
                RefreshTokenProvider = new TestAuthenticationTokenProvider(),
            });

            app.UseNancy(options => options.Bootstrapper = new NancyBootstrapper());
        }
    }
}