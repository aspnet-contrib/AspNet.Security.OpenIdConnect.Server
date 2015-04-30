using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Jwt;
using Mvc.Server.Providers;
using NWebsec.Owin;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Mvc.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            var certificate = GetCertificate();
            var credentials = new X509SigningCredentials(certificate);

            app.Map("/api", map => {
                var configuration = new HttpConfiguration();
                configuration.MapHttpAttributeRoutes();
                configuration.EnsureInitialized();

                map.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions {
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = new[] { "http://localhost:54540/" },
                    IssuerSecurityTokenProviders = new[] { new X509CertificateSecurityTokenProvider("http://localhost:54540/", certificate) }
                });

                map.UseWebApi(configuration);
            });

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

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions {
                ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com",
                ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f"
            });

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
                AuthenticationMode = AuthenticationMode.Passive,

                Issuer = "http://localhost:54540/",
                SigningCredentials = credentials,

                Provider = new AuthorizationProvider(),
                AccessTokenLifetime = TimeSpan.FromDays(14),
                IdentityTokenLifetime = TimeSpan.FromMinutes(60),
                AllowInsecureHttp = true,

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                ApplicationCanDisplayErrors = true
            });
        }

        private static X509Certificate2 GetCertificate() {
            // Note: in a real world app, you'd probably prefer storing the X.509 certificate
            // in the user or machine store. To keep this sample easy to use, the certificate
            // is extracted from the Certificate.pfx file embedded in this assembly.
            using (var stream = typeof(Startup).Assembly.GetManifestResourceStream("Mvc.Server.Certificate.pfx"))
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);
                buffer.Flush();

                return new X509Certificate2(
                    rawData: buffer.GetBuffer(),
                    password: "Owin.Security.OpenIdConnect.Server");
            }
        }
    }
}