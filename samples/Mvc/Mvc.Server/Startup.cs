using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Security;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.Framework.DependencyInjection;
using Mvc.Server.Models;
using Mvc.Server.Providers;

namespace Mvc.Server {
    public class Startup {
        public void Configure(IApplicationBuilder app) {
            X509Certificate2 certificate;

            // Note: in a real world app, you'd probably prefer storing the X.509 certificate
            // in the user or machine store. To keep this sample easy to use, the certificate
            // is extracted from the Certificate.pfx file embedded in this assembly.
            using (var stream = typeof(Startup).Assembly.GetManifestResourceStream("Certificate.pfx"))
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);
                buffer.Flush();

                certificate = new X509Certificate2(
                    rawData: buffer.GetBuffer(),
                    password: "Owin.Security.OpenIdConnect.Server");
            }

            var credentials = new X509SigningCredentials(certificate);

            app.UseServices(services => {
                services.AddEntityFramework()
                    .AddInMemoryStore()
                    .AddDbContext<ApplicationContext>();

                services.Configure<ExternalAuthenticationOptions>(options => {
                    options.SignInAsAuthenticationType = "ServerCookie";
                });

                services.AddMvc();
            });

            app.Map("/api", map => {
                map.UseOAuthBearerAuthentication(options => {
                    options.AuthenticationMode = AuthenticationMode.Active;
                });

                map.UseMvc();
            });

            // Insert a new cookies middleware in the pipeline to store
            // the user identity returned by the external identity provider.
            app.UseCookieAuthentication(options => {
                options.AuthenticationMode = AuthenticationMode.Active;
                options.AuthenticationType = "ServerCookie";
                options.CookieName = CookieAuthenticationDefaults.CookiePrefix + "ServerCookie";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.LoginPath = new PathString("/signin");
            });

            app.UseGoogleAuthentication(options => {
                options.ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com";
                options.ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f";
            });

            app.UseTwitterAuthentication(options => {
                options.ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g";
                options.ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI";
            });

            app.UseOpenIdConnectServer(options => {
                options.AuthenticationType = OpenIdConnectDefaults.AuthenticationType;

                options.Issuer = "http://localhost:12345/";
                options.SigningCredentials = credentials;

                options.Provider = new CustomOpenIdConnectServerProvider(app.ApplicationServices.GetRequiredService<IServiceScopeFactory>());
                options.AccessTokenLifetime = TimeSpan.FromDays(14);
                options.IdentityTokenLifetime = TimeSpan.FromMinutes(60);
                options.AllowInsecureHttp = true;

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AuthorizationCodeProvider = new AuthorizationCodeProvider(app.ApplicationServices.GetRequiredService<IServiceScopeFactory>());
            });

            app.UseStaticFiles();

            app.UseMvc();

            app.UseWelcomePage();

            using (var database = app.ApplicationServices.GetService<ApplicationContext>()) {
                database.Applications.Add(new Application {
                    ApplicationID = "myClient",
                    DisplayName = "My client application",
                    RedirectUri = "http://localhost:53507/oidc",
                    Secret = "secret_secret_secret"
                });

                database.SaveChanges();
            }
        }
    }
}