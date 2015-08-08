using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json.Linq;
using Owin;

namespace Mvc.Client {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType("ClientCookie");

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "ClientCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            // Insert a new OIDC client middleware in the pipeline.
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),

                // Note: these settings must match the application details inserted in
                // the database at the server level (see ApplicationContextInitializer.cs).
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                RedirectUri = "http://localhost:56854/oidc",
                PostLogoutRedirectUri = "http://localhost:56854/",

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                Authority = "http://localhost:54540/",
                
                // Note: the resource property represents the different endpoints the
                // access token should be issued for (values must be space-delimited).
                Resource = "http://localhost:54540/",

                Notifications = new OpenIdConnectAuthenticationNotifications {
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
                    AuthorizationCodeReceived = async notification => {
                        using (var client = new HttpClient()) {
                            var configuration = await notification.Options.ConfigurationManager.GetConfigurationAsync(notification.Request.CallCancelled);

                            var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
                            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                                { OpenIdConnectParameterNames.ClientId, notification.Options.ClientId },
                                { OpenIdConnectParameterNames.ClientSecret, notification.Options.ClientSecret },
                                { OpenIdConnectParameterNames.Code, notification.ProtocolMessage.Code },
                                { OpenIdConnectParameterNames.GrantType, "authorization_code" },
                                { OpenIdConnectParameterNames.RedirectUri, notification.Options.RedirectUri }
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
                    RedirectToIdentityProvider = notification => {
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest) {
                            var token = notification.OwinContext.Authentication.User.FindFirst(OpenIdConnectParameterNames.IdToken);
                            if (token != null) {
                                notification.ProtocolMessage.IdTokenHint = token.Value;
                            }
                        }

                        return Task.FromResult<object>(null);
                    }
                }
            });
        }
    }
}