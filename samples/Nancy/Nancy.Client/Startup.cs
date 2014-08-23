using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace Nancy.Client {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureOidcClientDemo(app);
        }

        private static void ConfigureOidcClientDemo(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType("ClientCookie");

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirect from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "ClientCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            var provider = new RSACryptoServiceProvider(4096) { PersistKeyInCsp = false };
            provider.FromXmlString("<RSAKeyValue><Modulus>vJC1K4oRr/WY1PBnPUiHmvWBuAuZt/q11nf+fAtn1S8IclTjzNpH5X4qCEKHTNVmpsSf3S6rQkPXkpNhAbkyLl4RhKQfojQCybevvXz5oXuX7hMCaiRKLTnq5+/ZFHZwC0ysgyLJcT7uwYnqhHg7cRwrTlVl7KcxU37nIu/xj1RCjjrND5hjTMnlvGe+eyZqMpTBj8BEZZqfW0yo54Qt1mqExv1WIlqsFQ+kl9J2sfeSkqxiI654Tq8Ie416yHqT3FahebZp334hN9t2cbRJ+Cg9hI1Nwee73c1hyCVBjy6j3PG9pg68D2f3joZrq2sRBeGQjAnZY6rwCU58KXlDdEJF1jVlyFfFexL5pOtYjRx3nG14WuyKlfuHnPFY79DZ/wjWXdeR9prMo2D/UkqJayC1vXWfWDGSnm6gKJUd2ZvpQtvfdUA4aStIZXjQ1RbxxyQSFNfeHhMAJpIaslVI40NIZ+Qk4DApIDOqw8DDeL8J3RnRbaQUG1XzDDObW/pfSVfQZP2sNsaWgwMd5kMo7DjzTCWcwSCDccx9Jt9APlSkkKs+aiGTgYu2i7Y3BjZA25gBjCMDFDdUIUn3qyNR0fwkf4yxaybDlHYselDUlQDkACuHbQVIHkCLetNNDI0WiJuMAG9+168W4utWnfoa5W2ALncIdfjWopGqhjcx13k=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>");

            var key = new RsaSecurityKey(provider);

            // Insert a new OIDC client middleware in the pipeline.
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),

                // Note: these settings must match the application details inserted in
                // the database at the server level (see ApplicationContextInitializer.cs).
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                RedirectUri = "http://localhost:56765/oidc",

                Scope = "openid",

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                Authority = "http://localhost:55938/"
            });

            app.UseNancy(options => options.PerformPassThrough = context => context.Response.StatusCode == HttpStatusCode.NotFound);
        }
    }
}