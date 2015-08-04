using System;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Cryptography;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Data.Entity;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Dnx.Runtime;
using Mvc.Server.Extensions;
using Mvc.Server.Models;
using Mvc.Server.Providers;

#if !DNXCORE50
using NWebsec.Owin;
#endif

namespace Mvc.Server {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            services.AddEntityFramework()
                .AddInMemoryDatabase()
                .AddDbContext<ApplicationContext>(options => {
                    options.UseInMemoryDatabase();
                });

            services.Configure<SharedAuthenticationOptions>(options => {
                options.SignInScheme = "ServerCookie";
            });

            services.AddAuthentication();
            services.AddCaching();
            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IRuntimeEnvironment environment) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            // Create a new branch where the registered middleware will be executed only for API calls.
            app.UseWhen(context => context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                branch.UseOAuthBearerAuthentication(options => {
                    options.AutomaticAuthentication = true;
                    options.Audience = "http://localhost:54540/";
                    options.Authority = "http://localhost:54540/";
                });
            });

            // Create a new branch where the registered middleware will be executed only for non API calls.
            app.UseWhen(context => !context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                // Insert a new cookies middleware in the pipeline to store
                // the user identity returned by the external identity provider.
                branch.UseCookieAuthentication(options => {
                    options.AutomaticAuthentication = true;
                    options.AuthenticationScheme = "ServerCookie";
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

#if !DNXCORE50
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
                options.AuthenticationScheme = OpenIdConnectDefaults.AuthenticationScheme;

                // There's currently a bug in System.IdentityModel.Tokens that prevents using X509 certificates on Mono.
                // To work around this bug, a new in-memory RSA key is generated each time this app is started.
                // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/179
                if (string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase)) {
                    var rsaCryptoServiceProvider = new RSACryptoServiceProvider(2048);
                    var rsaParameters = rsaCryptoServiceProvider.ExportParameters(includePrivateParameters: true);

                    options.UseKey(new RsaSecurityKey(rsaParameters));
                }

                else {
                    options.UseCertificate(
                        assembly: typeof(Startup).GetTypeInfo().Assembly,
                        resource: "Mvc.Server.Certificate.pfx",
                        password: "Owin.Security.OpenIdConnect.Server");
                }

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;

                options.Provider = new AuthorizationProvider();
            });

            app.UseStaticFiles();

            app.UseMvc();

            app.UseWelcomePage();

            using (var database = app.ApplicationServices.GetService<ApplicationContext>()) {
                database.Applications.Add(new Application {
                    ApplicationID = "myClient",
                    DisplayName = "My client application",
                    RedirectUri = "http://localhost:53507/oidc",
                    LogoutRedirectUri = "http://localhost:53507/",
                    Secret = "secret_secret_secret"
                });

                database.SaveChanges();
            }
        }
    }
}