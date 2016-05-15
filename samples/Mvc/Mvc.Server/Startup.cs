using System;
using System.Reflection;
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
                    LoginPath = new PathString("/signin"),
                    LogoutPath = new PathString("/signout")
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

            app.UseOpenIdConnectServer(options => {
                options.Provider = new AuthorizationProvider();

                // Register the embedded X.509 certificate used to sign the JWT tokens.
                // Note: this certificate is a TEST certificate: NEVER USE IT ON PRODUCTION.
                // Instead, generate a self-signed certificate using Pluralsight's self-cert utility:
                // https://s3.amazonaws.com/pluralsight-free/keith-brown/samples/SelfCert.zip
                options.SigningCredentials.AddCertificate(
                    assembly: typeof(Startup).GetTypeInfo().Assembly,
                    resource: "Mvc.Server.Certificate.pfx",
                    password: "Owin.Security.OpenIdConnect.Server");

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;
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