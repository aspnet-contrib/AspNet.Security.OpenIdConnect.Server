using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Security;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.AspNet.Security.OAuth;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.Logging.Console;
using Newtonsoft.Json.Linq;

namespace Mvc.Client {
    public class Startup {
        public void Configure(IApplicationBuilder app) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            app.UseServices(services => {
                services.Configure<ExternalAuthenticationOptions>(options => {
                    options.SignInAsAuthenticationType = "ClientCookie";
                });

                services.AddMvc();
            });

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(options => {
                options.AuthenticationMode = AuthenticationMode.Active;
                options.AuthenticationType = "ClientCookie";
                options.CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            });

            app.UseOAuthAuthentication("OpenIdConnect", options => {
                options.AuthenticationMode = AuthenticationMode.Active;
                options.Notifications = new OAuthAuthenticationNotifications();

                // Note: these settings must match the application
                // details inserted in the database at the server level.
                options.ClientId = "myClient";
                options.ClientSecret = "secret_secret_secret";
                options.CallbackPath = new PathString("/oidc");
                options.AuthorizationEndpoint = "http://localhost:54540/connect/authorize";
                options.TokenEndpoint = "http://localhost:54540/connect/token";

                options.Scope.Add("profile");

                options.Notifications = new OAuthAuthenticationNotifications {
                    OnGetUserInformationAsync = async context => {
                        var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:54540/api/claims");
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

                        var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        if (context.Identity == null) {
                            context.Identity = new ClaimsIdentity(context.Options.AuthenticationType);
                        }

                        // Add the access token to the returned ClaimsIdentity to make it easier to retrieve.
                        // Note: this is automatically done by OAuthAuthenticationDefaults.DefaultOnGetUserInformationAsync
                        // (from Microsoft.AspNet.Security.OAuth) when you don't provide an explicit notification.
                        context.Identity.AddClaim(new Claim(type: "access_token", value: context.AccessToken));

                        // Extract the list of claims returned by the remote api/claims endpoint.
                        foreach (JToken claim in JArray.Parse(await response.Content.ReadAsStringAsync())) {
                            context.Identity.AddClaim(new Claim(
                                type: claim.Value<string>(nameof(Claim.Type)),
                                value: claim.Value<string>(nameof(Claim.Value)),
                                valueType: claim.Value<string>(nameof(Claim.ValueType)),
                                issuer: claim.Value<string>(nameof(Claim.Issuer))));
                        }
                    }
                };
            });

            app.UseStaticFiles();

            app.UseMvc();
        }
    }
}