using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Mvc.Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "ClientCookie";
            })

            .AddCookie("ClientCookie", options =>
            {
                options.Cookie.Name = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.LoginPath = new PathString("/signin");
                options.LogoutPath = new PathString("/signout");
            })

            .AddOpenIdConnect(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;

                // Note: these settings must match the application details
                // inserted in the database at the server level.
                options.ClientId = "myClient";
                options.ClientSecret = "secret_secret_secret";

                // Use the authorization code flow.
                options.ResponseType = OpenIdConnectResponseType.Code;

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                options.Authority = "http://localhost:54540/";

                options.SecurityTokenValidator = new JwtSecurityTokenHandler
                {
                    // Disable the built-in JWT claims mapping feature.
                    InboundClaimTypeMap = new Dictionary<string, string>()
                };

                options.TokenValidationParameters.NameClaimType = "name";
                options.TokenValidationParameters.RoleClaimType = "role";
            });

            services.AddMvc();

            services.AddSingleton<HttpClient>();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseAuthentication();

            app.UseStaticFiles();

            app.UseMvc();
        }
    }
}
