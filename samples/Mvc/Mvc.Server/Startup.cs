using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Mvc.Server.Models;
using Mvc.Server.Providers;

namespace Mvc.Server
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddEntityFrameworkInMemoryDatabase()
                .AddDbContext<ApplicationContext>(options =>
                {
                    options.UseInMemoryDatabase(nameof(ApplicationContext));
                });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "ServerCookie";
            })

            .AddCookie("ServerCookie", options =>
            {
                options.Cookie.Name = CookieAuthenticationDefaults.CookiePrefix + "ServerCookie";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.LoginPath = new PathString("/signin");
                options.LogoutPath = new PathString("/signout");
            })

            .AddGoogle(options =>
            {
                options.ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com";
                options.ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f";
            })

            .AddTwitter(options =>
            {
                options.ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g";
                options.ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI";
            })

            .AddOAuthValidation()

            .AddOpenIdConnectServer(options =>
            {
                options.ProviderType = typeof(AuthorizationProvider);

                // Enable the authorization, logout, token and userinfo endpoints.
                options.AuthorizationEndpointPath = "/connect/authorize";
                options.LogoutEndpointPath = "/connect/logout";
                options.TokenEndpointPath = "/connect/token";
                options.UserinfoEndpointPath = "/connect/userinfo";

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;

                // Note: to override the default access token format and use JWT, assign AccessTokenHandler:
                //
                // options.AccessTokenHandler = new JwtSecurityTokenHandler
                // {
                //     InboundClaimTypeMap = new Dictionary<string, string>(),
                //     OutboundClaimTypeMap = new Dictionary<string, string>()
                // };
                //
                // Note: when using JWT as the access token format, you have to register a signing key.
                //
                // You can register a new ephemeral key, that is discarded when the application shuts down.
                // Tokens signed using this key are automatically invalidated and thus this method
                // should only be used during development:
                //
                // options.SigningCredentials.AddEphemeralKey();
                //
                // On production, using a X.509 certificate stored in the machine store is recommended.
                // You can generate a self-signed certificate using Pluralsight's self-cert utility:
                // https://s3.amazonaws.com/pluralsight-free/keith-brown/samples/SelfCert.zip
                //
                // options.SigningCredentials.AddCertificate("7D2A741FE34CC2C7369237A5F2078988E17A6A75");
                //
                // Alternatively, you can also store the certificate as an embedded .pfx resource
                // directly in this assembly or in a file published alongside this project:
                //
                // options.SigningCredentials.AddCertificate(
                //     assembly: typeof(Startup).GetTypeInfo().Assembly,
                //     resource: "Mvc.Server.Certificate.pfx",
                //     password: "Owin.Security.OpenIdConnect.Server");
            });

            services.AddScoped<AuthorizationProvider>();

            services.AddMvc();

            services.AddDistributedMemoryCache();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseAuthentication();

            app.UseStaticFiles();

            app.UseMvc();

            app.UseWelcomePage();

            using (var database = app.ApplicationServices.GetService<ApplicationContext>())
            {
                // Note: when using the introspection middleware, your resource server
                // MUST be registered as an OAuth2 client and have valid credentials.
                //
                // database.Applications.Add(new Application
                // {
                //     ApplicationID = "resource_server",
                //     DisplayName = "Main resource server",
                //     Secret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd"
                // });

                database.Applications.Add(new Application
                {
                    ApplicationID = "myClient",
                    DisplayName = "My client application",
                    RedirectUri = "http://localhost:53507/signin-oidc",
                    LogoutRedirectUri = "http://localhost:53507/signout-callback-oidc",
                    Secret = "secret_secret_secret"
                });

                database.SaveChanges();
            }
        }
    }
}
