using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Authentication.OpenIdConnect;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Dnx.Runtime;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;

namespace Mvc.Client {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            services.Configure<SharedAuthenticationOptions>(options => {
                options.SignInScheme = "ClientCookie";
            });

            services.AddAuthentication();

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IRuntimeEnvironment environment) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();
            
            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(options => {
                options.AutomaticAuthentication = true;
                options.AuthenticationScheme = "ClientCookie";
                options.CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.LoginPath = new PathString("/signin");
            });

            app.UseOpenIdConnectAuthentication(options => {
                options.AuthenticationScheme = OpenIdConnectAuthenticationDefaults.AuthenticationScheme;

                // Note: these settings must match the application details
                // inserted in the database at the server level.
                options.ClientId = "myClient";
                options.ClientSecret = "secret_secret_secret";
                options.RedirectUri = "http://localhost:53507/oidc";
                options.PostLogoutRedirectUri = "http://localhost:53507/";

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                options.Authority = "http://localhost:54540/";

                // Note: the resource property represents the different endpoints the
                // access token should be issued for (values must be space-delimited).
                options.Resource = "http://localhost:54540/";

                options.Notifications = new OpenIdConnectAuthenticationNotifications();

                // Note: by default, the OIDC client throws an OpenIdConnectProtocolException
                // when an error occurred during the authentication/authorization process.
                // To prevent a YSOD from being displayed, the response is declared as handled.
                options.Notifications.AuthenticationFailed = notification => {
                    if (string.Equals(notification.ProtocolMessage.Error, "access_denied", StringComparison.Ordinal)) {
                        notification.HandleResponse();

                        notification.Response.Redirect("/");
                    }

                    return Task.FromResult<object>(null);
                };

                // Retrieve an access token from the remote token endpoint
                // using the authorization code received during the current request.
                options.Notifications.AuthorizationCodeReceived = async notification => {
                    using (var client = new HttpClient()) {
                        var configuration = await notification.Options.ConfigurationManager.GetConfigurationAsync(notification.HttpContext.RequestAborted);

                        var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
                        request.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                            [OpenIdConnectParameterNames.ClientId] = notification.Options.ClientId,
                            [OpenIdConnectParameterNames.ClientSecret] = notification.Options.ClientSecret,
                            [OpenIdConnectParameterNames.Code] = notification.ProtocolMessage.Code,
                            [OpenIdConnectParameterNames.GrantType] = "authorization_code",
                            [OpenIdConnectParameterNames.RedirectUri] = notification.Options.RedirectUri
                        });

                        var response = await client.SendAsync(request, notification.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
                        
                        // Add the access token to the returned ClaimsIdentity to make it easier to retrieve.
                        var identity = notification.AuthenticationTicket.Principal.Identity as ClaimsIdentity;
                        if (identity == null) {
                            throw new InvalidOperationException();
                        }

                        identity.AddClaim(new Claim(
                            type: OpenIdConnectParameterNames.AccessToken,
                            value: payload.Value<string>(OpenIdConnectParameterNames.AccessToken)));
                    }
                };

                if (string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase)) {
                    options.SecurityTokenValidators = new[] { new UnsafeJwtSecurityTokenHandler() };
                }
            });

            app.UseStaticFiles();

            app.UseMvc();
        }

        // There's currently a bug on Mono that prevents ValidateSignature from working correctly.
        // To work around this bug, signature validation is temporarily disabled: of course,
        // NEVER do that in a real world application as it opens a huge security hole.
        // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/179
        private class UnsafeJwtSecurityTokenHandler : JwtSecurityTokenHandler {
            protected override JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters) {
                return ReadToken(token) as JwtSecurityToken;
            }
        }
    }
}