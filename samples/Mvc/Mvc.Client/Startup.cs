using System;
using System.Collections.Generic;
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
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
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
                options.AuthenticationScheme = OpenIdConnectDefaults.AuthenticationScheme;

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

                options.Events = new OpenIdConnectEvents {
                    // Note: by default, the OIDC client throws an OpenIdConnectProtocolException
                    // when an error occurred during the authentication/authorization process.
                    // To prevent a YSOD from being displayed, the response is declared as handled.
                    OnAuthenticationFailed = context => {
                        if (string.Equals(context.ProtocolMessage.Error, "access_denied", StringComparison.Ordinal)) {
                            context.HandleResponse();

                            context.Response.Redirect("/");
                        }

                        return Task.FromResult<object>(null);
                    },

                    // Retrieve an access token from the remote token endpoint
                    // using the authorization code received during the current request.
                    OnAuthorizationCodeReceived = async context => {
                        using (var client = new HttpClient()) {
                            var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);

                            var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
                            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                                [OpenIdConnectParameterNames.ClientId] = context.Options.ClientId,
                                [OpenIdConnectParameterNames.ClientSecret] = context.Options.ClientSecret,
                                [OpenIdConnectParameterNames.Code] = context.ProtocolMessage.Code,
                                [OpenIdConnectParameterNames.GrantType] = "authorization_code",
                                [OpenIdConnectParameterNames.RedirectUri] = context.Options.RedirectUri
                            });

                            var response = await client.SendAsync(request, context.HttpContext.RequestAborted);
                            response.EnsureSuccessStatusCode();

                            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

                            var identity = context.AuthenticationTicket.Principal.Identity as ClaimsIdentity;
                            if (identity == null) {
                                throw new InvalidOperationException();
                            }

                            // Add the access token to the returned ClaimsIdentity to make it easier to retrieve.
                            identity.AddClaim(new Claim(
                                type: OpenIdConnectParameterNames.AccessToken,
                                value: payload.Value<string>(OpenIdConnectParameterNames.AccessToken)));

                            // Add the identity token to the returned ClaimsIdentity to make it easier to retrieve.
                            identity.AddClaim(new Claim(
                                type: OpenIdConnectParameterNames.IdToken,
                                value: payload.Value<string>(OpenIdConnectParameterNames.IdToken)));
                        }
                    },

                    // Attach the id_token stored in the authentication cookie to the logout request.
                    OnRedirectToIdentityProvider = context => {
                        if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest) {
                            var token = context.HttpContext.User.FindFirst(OpenIdConnectParameterNames.IdToken);
                            if (token != null) {
                                context.ProtocolMessage.IdTokenHint = token.Value;
                            }
                        }

                        return Task.FromResult<object>(null);
                    },
                };
            });

            app.UseStaticFiles();

            app.UseMvc();
        }
    }
}