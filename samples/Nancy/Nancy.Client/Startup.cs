using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json.Linq;
using Owin;

namespace Nancy.Client
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType("ClientCookie");

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "ClientCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            // Insert a new OIDC client middleware in the pipeline.
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                Authority = "http://localhost:54541/",
                RequireHttpsMetadata = false,

                // Note: these settings must match the application details inserted in
                // the database at the server level (see ApplicationContextInitializer.cs).
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                RedirectUri = "http://localhost:56765/oidc",
                PostLogoutRedirectUri = "http://localhost:56765/",

                Scope = "openid profile offline_access",

                SecurityTokenValidator = new JwtSecurityTokenHandler
                {
                    // Disable the built-in JWT claims mapping feature.
                    InboundClaimTypeMap = new Dictionary<string, string>()
                },

                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                },

                // Note: by default, the OIDC client throws an OpenIdConnectProtocolException
                // when an error occurred during the authentication/authorization process.
                // To prevent a YSOD from being displayed, the response is declared as handled.
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = notification =>
                    {
                        if (string.Equals(notification.ProtocolMessage.Error, "access_denied", StringComparison.Ordinal))
                        {
                            notification.HandleResponse();

                            notification.Response.Redirect("/");
                        }

                        return Task.CompletedTask;
                    },

                    // Retrieve an access token from the remote token endpoint
                    // using the authorization code received during the current request.
                    AuthorizationCodeReceived = async notification =>
                    {
                        using (var client = new HttpClient())
                        {
                            var configuration = await notification.Options.ConfigurationManager.GetConfigurationAsync(notification.Request.CallCancelled);

                            var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
                            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                            {
                                [OpenIdConnectParameterNames.ClientId] = notification.Options.ClientId,
                                [OpenIdConnectParameterNames.ClientSecret] = notification.Options.ClientSecret,
                                [OpenIdConnectParameterNames.Code] = notification.ProtocolMessage.Code,
                                [OpenIdConnectParameterNames.GrantType] = "authorization_code",
                                [OpenIdConnectParameterNames.RedirectUri] = notification.Options.RedirectUri
                            });

                            var response = await client.SendAsync(request, notification.Request.CallCancelled);
                            response.EnsureSuccessStatusCode();

                            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

                            // Add the access token to the returned ClaimsIdentity to make it easier to retrieve.
                            notification.AuthenticationTicket.Identity.AddClaim(new Claim(
                                type: OpenIdConnectParameterNames.AccessToken,
                                value: payload.Value<string>(OpenIdConnectParameterNames.AccessToken)));

                            // Add the identity token to the returned ClaimsIdentity to make it easier to retrieve.
                            notification.AuthenticationTicket.Identity.AddClaim(new Claim(
                                type: OpenIdConnectParameterNames.IdToken,
                                value: payload.Value<string>(OpenIdConnectParameterNames.IdToken)));
                        }
                    },

                    // Attach the id_token stored in the authentication cookie to the logout request.
                    RedirectToIdentityProvider = notification =>
                    {
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var token = notification.OwinContext.Authentication.User?.FindFirst(OpenIdConnectParameterNames.IdToken);
                            if (token != null)
                            {
                                notification.ProtocolMessage.IdTokenHint = token.Value;
                            }
                        }

                        return Task.CompletedTask;
                    }
                }
            });

            app.UseNancy(options =>
            {
                options.Bootstrapper = new NancyBootstrapper();
                options.PerformPassThrough = context => context.Response.StatusCode == HttpStatusCode.NotFound;
            });
        }
    }
}
