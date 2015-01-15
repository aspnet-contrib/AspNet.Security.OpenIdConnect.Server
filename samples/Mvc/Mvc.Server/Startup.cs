using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Security;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.Logging.Console;
using Mvc.Server.Extensions;
using Mvc.Server.Models;
using Mvc.Server.Providers;

#if ASPNET50
using NWebsec.Owin;
#endif

#if ASPNETCORE50
using Microsoft.AspNet.Security.OAuthBearer;
#endif

namespace Mvc.Server {
    public class Startup {
        public void Configure(IApplicationBuilder app) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            X509Certificate2 certificate;

            // Note: in a real world app, you'd probably prefer storing the X.509 certificate
            // in the user or machine store. To keep this sample easy to use, the certificate
            // is extracted from the Certificate.pfx file embedded in this assembly.
            using (var stream = typeof(Startup).GetTypeInfo().Assembly.GetManifestResourceStream("Certificate.pfx"))
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);
                buffer.Flush();

                certificate = new X509Certificate2(
                    rawData: buffer.ToArray(),
                    password: "Owin.Security.OpenIdConnect.Server");
            }

#if ASPNET50
            var credentials = new X509SigningCredentials(certificate);
#elif ASPNETCORE50
            var key = new X509SecurityKey(certificate);

            var credentials = new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest);
#endif

            app.UseServices(services => {
                services.AddEntityFramework()
                    .AddInMemoryStore()
                    .AddDbContext<ApplicationContext>();

                services.Configure<ExternalAuthenticationOptions>(options => {
                    options.SignInAsAuthenticationType = "ServerCookie";
                });

                services.AddDataProtection();

                services.AddMvc();
            });

#if ASPNETCORE50
            // Create a new branch where the registered middleware will be executed only for API calls.
            app.UseWhen(context => context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                branch.UseOAuthBearerAuthentication(options => {
                    options.AuthenticationMode = AuthenticationMode.Active;
                });
            });
#endif

            // Create a new branch where the registered middleware will be executed only for non API calls.
            app.UseWhen(context => !context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                // Insert a new cookies middleware in the pipeline to store
                // the user identity returned by the external identity provider.
                branch.UseCookieAuthentication(options => {
                    options.AuthenticationMode = AuthenticationMode.Active;
                    options.AuthenticationType = "ServerCookie";
                    options.CookieName = CookieAuthenticationDefaults.CookiePrefix + "ServerCookie";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                    options.LoginPath = new PathString("/signin");
                });

                branch.UseGoogleAuthentication(options => {
                    options.ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com";
                    options.ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f";
                });

                branch.UseTwitterAuthentication(options => {
                    options.ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g";
                    options.ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI";
                });
            });

#if ASPNET50
            app.UseOwinAppBuilder(owin => {
                // Insert a new middleware responsible of setting the Content-Security-Policy header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
                owin.UseCsp(options => options.DefaultSources(configuration => configuration.Self())
                                              .ImageSources(configuration => configuration.Self().CustomSources("*"))
                                              .ScriptSources(configuration => configuration.UnsafeInline())
                                              .StyleSources(configuration => configuration.Self().UnsafeInline()));

                // Insert a new middleware responsible of setting the X-Content-Type-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXContentTypeOptions();

                // Insert a new middleware responsible of setting the X-Frame-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXfo(options => options.Deny());

                // Insert a new middleware responsible of setting the X-Xss-Protection header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXXssProtection(options => options.EnabledWithBlockMode());
            });
#endif

            app.UseOpenIdConnectServer(options => {
                options.AuthenticationType = OpenIdConnectDefaults.AuthenticationType;

                options.Issuer = "http://localhost:54540/";
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