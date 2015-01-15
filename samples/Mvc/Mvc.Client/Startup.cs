using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Security;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.AspNet.Security.OpenIdConnect;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.Logging.Console;
using Microsoft.IdentityModel.Protocols;
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

                services.AddDataProtection();

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

            app.UseOpenIdConnectAuthentication(options => {
                options.AuthenticationMode = AuthenticationMode.Active;
                options.AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType;

                // Note: these settings must match the application details inserted in
                // the database at the server level (see ApplicationContextInitializer.cs).
                options.ClientId = "myClient";
                options.ClientSecret = "secret_secret_secret";
                options.RedirectUri = "http://localhost:53507/oidc";

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                options.Authority = "http://localhost:54540/";

                options.Notifications = new OpenIdConnectAuthenticationNotifications {
                    // Note: by default, the OIDC client throws an OpenIdConnectProtocolException
                    // when an error occurred during the authentication/authorization process.
                    // To prevent a YSOD from being displayed, the response is declared as handled.
                    AuthenticationFailed = notification => {
                        if (string.Equals(notification.ProtocolMessage.Error, "access_denied", StringComparison.Ordinal)) {
                            notification.HandleResponse();

                            notification.Response.Redirect("/");
                        }

                        return Task.FromResult<object>(null);
                    },

                    // Retrieve an access token from the remote token endpoint
                    // using the authorization code received during the current request.
                    SecurityTokenValidated = async notification => {
                        using (var client = new HttpClient()) {
                            var configuration = await notification.Options.ConfigurationManager.GetConfigurationAsync(notification.HttpContext.RequestAborted);

                            var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
                            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                                { OpenIdConnectParameterNames.ClientId, notification.Options.ClientId },
                                { OpenIdConnectParameterNames.ClientSecret, notification.Options.ClientSecret },
                                { OpenIdConnectParameterNames.Code, notification.ProtocolMessage.Code },
                                { OpenIdConnectParameterNames.GrantType, "authorization_code" },
                                { OpenIdConnectParameterNames.RedirectUri, notification.Options.RedirectUri }
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
                    }
                };
            });

            app.UseStaticFiles();

            app.UseMvc();
        }
    }
}