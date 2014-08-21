using System;
using System.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Nancy.Owin;
using Nancy.Server.Providers;
using NWebsec.Owin;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            // You can easily generate a new base64-encoded key using RNGCryptoServiceProvider:
            //using (var generator = new RNGCryptoServiceProvider()) {
            //    var buffer = new byte[256 / 8];
            //    generator.GetBytes(buffer);
            //    Console.WriteLine(Convert.ToBase64String(buffer));
            //}

            var key = new InMemorySymmetricSecurityKey(Convert.FromBase64String("Srtjyi8wMFfmP9Ub8U2ieVGAcrP/7gK3VM/K6KfJ/fI="));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

            app.SetDefaultSignInAsAuthenticationType("ServerCookie");

            // Insert a new cookies middleware in the pipeline to store
            // the user identity returned by the external identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "ServerCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ServerCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
                LoginPath = new PathString("/signin")
            });

            app.UseGoogleAuthentication();

            // Insert a new middleware responsible of setting the Content-Security-Policy header.
            // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
            app.UseCsp(options => options.DefaultSources(configuration => configuration.Self())
                                         .ScriptSources(configuration => configuration.UnsafeInline()));

            // Insert a new middleware responsible of setting the X-Content-Type-Options header.
            // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
            app.UseXContentTypeOptions();

            // Insert a new middleware responsible of setting the X-Frame-Options header.
            // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
            app.UseXfo(options => options.Deny());

            // Insert a new middleware responsible of setting the X-Xss-Protection header.
            // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
            app.UseXXssProtection(options => options.EnabledWithBlockMode());

            app.UseOpenIdConnectServer(new OpenIdConnectServerOptions {
                AuthenticationType = OpenIdConnectDefaults.AuthenticationType,
                IdTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                IssuerName = "urn:authServer",

                // Note: these settings must match the endpoints and the token
                // parameters defined in Startup.cs at the client level.
                TokenEndpointPath = new PathString("/oauth2/access_token"),
                AuthorizeEndpointPath = new PathString("/oauth2/authorize"),
                SigningCredentials = credentials,

                Provider = new CustomOpenIdConnectServerProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true,

                // Note: see AuthorizationModule.cs for more
                // information concerning ApplicationCanDisplayErrors.
                ApplicationCanDisplayErrors = true,
                AuthorizationCodeProvider = new AuthorizationCodeProvider()
            });

            app.UseNancy(options => options.Bootstrapper = new NancyBootstrapper());
        }
    }
}