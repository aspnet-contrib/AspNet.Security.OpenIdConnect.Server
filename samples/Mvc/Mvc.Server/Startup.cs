using System;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Mvc.Server.Extensions;
using Mvc.Server.Models;
using Mvc.Server.Providers;

#if DNX451
using NWebsec.Owin;
#endif

namespace Mvc.Server {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            services.AddEntityFramework()
                .AddEntityFrameworkInMemoryDatabase()
                .AddDbContext<ApplicationContext>(options => {
                    options.UseInMemoryDatabase();
                });

            services.AddAuthentication(options => {
                options.SignInScheme = "ServerCookie";
            });

            services.AddDistributedMemoryCache();
            services.AddMvc();
            services.AddMvcDnx();
        }

        public void Configure(IApplicationBuilder app) {
            app.UseDeveloperExceptionPage();

            // Create a new branch where the registered middleware will be executed only for API calls.
            app.UseWhen(context => context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                branch.UseOAuthValidation(new OAuthValidationOptions {
                    AutomaticAuthenticate = true,
                    AutomaticChallenge = true
                });

                // Alternatively, you can also use the introspection middleware.
                // Using it is recommended if your resource server is in a
                // different application/separated from the authorization server.
                // 
                // branch.UseOAuthIntrospection(new OAuthIntrospectionOptions {
                //     AutomaticAuthenticate = true,
                //     AutomaticChallenge = true,
                //     Authority = "http://localhost:54540/",
                //     Audiences = { "resource_server" },
                //     ClientId = "resource_server",
                //     ClientSecret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd"
                // });
            });

            // Create a new branch where the registered middleware will be executed only for non API calls.
            app.UseWhen(context => !context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                // Insert a new cookies middleware in the pipeline to store
                // the user identity returned by the external identity provider.
                branch.UseCookieAuthentication(new CookieAuthenticationOptions {
                    AutomaticAuthenticate = true,
                    AutomaticChallenge = true,
                    AuthenticationScheme = "ServerCookie",
                    CookieName = CookieAuthenticationDefaults.CookiePrefix + "ServerCookie",
                    ExpireTimeSpan = TimeSpan.FromMinutes(5),
                    LoginPath = new PathString("/signin")
                });

                branch.UseGoogleAuthentication(new GoogleOptions {
                    ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com",
                    ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f"
                });

                branch.UseTwitterAuthentication(new TwitterOptions {
                    ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g",
                    ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI"
                });
            });

#if DNX451
            app.UseOwinAppBuilder(owin => {
                // Insert a new middleware responsible of setting the Content-Security-Policy header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
                owin.UseCsp(options => options.DefaultSources(configuration => configuration.Self())
                                              .ImageSources(configuration => configuration.Self().CustomSources("data:"))
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
                options.Provider = new AuthorizationProvider();

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;

                // Note: by default, tokens are signed using dynamically-generated
                // RSA keys but you can also use your own certificate:
                // 
                // options.SigningCredentials.AddCertificate(certificate);
            });

            app.UseStaticFiles();

            app.UseMvc();

            app.UseWelcomePage();

            using (var database = app.ApplicationServices.GetService<ApplicationContext>()) {
                // Note: when using the introspection middleware, your resource server
                // MUST be registered as an OAuth2 client and have valid credentials.
                // 
                // database.Applications.Add(new Application {
                //     ApplicationID = "resource_server",
                //     DisplayName = "Main resource server",
                //     Secret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd"
                // });

                database.Applications.Add(new Application {
                    ApplicationID = "myClient",
                    DisplayName = "My client application",
                    RedirectUri = "http://localhost:53507/signin-oidc",
                    LogoutRedirectUri = "http://localhost:53507/",
                    Secret = "secret_secret_secret"
                });

                database.SaveChanges();
            }
        }
    }
}