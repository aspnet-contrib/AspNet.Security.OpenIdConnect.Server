using System;
using System.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace Basic.Client {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirect from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Passive,
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            // Note: symmetric keys can only be used when the identity provider and the client applications
            // trust each other and are part of the same trusted boundary (typically, a website façade and its backend server).
            // For every other use, use an asymmetric security key like RsaSecurityKey or X509SecurityKey.
            // See the Nancy.Server sample for a complete sample using a X.509 certificate.
            var key = new InMemorySymmetricSecurityKey(Convert.FromBase64String("Srtjyi8wMFfmP9Ub8U2ieVGAcrP/7gK3VM/K6KfJ/fI="));

            // Insert a new OIDC client middleware in the pipeline.
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),

                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                RedirectUri = "http://localhost:57264/oidc",

                Scope = "openid",
                Authority = "http://localhost:59504/",

                // Note: given that Basic.Server uses a symmetric key that cannot be shared publicly,
                // the automatic configuration discovery won't be able to retrive the token
                // validation parameters: you need to set them here explicitly.
                TokenValidationParameters = new TokenValidationParameters() {
                    ValidAudience = "myClient",
                    ValidIssuer = "http://localhost:59504/",
                    IssuerSigningKey = key
                }
            });
        }
    }
}