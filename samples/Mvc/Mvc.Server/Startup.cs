using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Data.Entity;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.Runtime;
using Mvc.Server.Extensions;
using Mvc.Server.Models;
using Mvc.Server.Providers;

#if !DNXCORE50
using NWebsec.Owin;
#endif

namespace Mvc.Server {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            services.AddEntityFramework()
                .AddInMemoryDatabase()
                .AddDbContext<ApplicationContext>(options => {
                    options.UseInMemoryDatabase();
                });

            services.Configure<ExternalAuthenticationOptions>(options => {
                options.SignInScheme = "ServerCookie";
            });

            services.AddAuthentication();
            services.AddCaching();
            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IRuntimeEnvironment environment) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            var certificate = LoadCertificate(environment);
            var key = new X509SecurityKey(certificate);

            var credentials = new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest);

            // Create a new branch where the registered middleware will be executed only for API calls.
            app.UseWhen(context => context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                branch.UseOAuthBearerAuthentication(options => {
                    options.AutomaticAuthentication = true;
                    options.Audience = "http://localhost:54540/";
                    options.Authority = "http://localhost:54540/";

                    if (string.Equals(environment.RuntimeType, "CoreCLR", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase)) {
                        options.SecurityTokenValidators = new[] { new UnsafeJwtSecurityTokenHandler() };
                    }
                });
            });

            // Create a new branch where the registered middleware will be executed only for non API calls.
            app.UseWhen(context => !context.Request.Path.StartsWithSegments(new PathString("/api")), branch => {
                // Insert a new cookies middleware in the pipeline to store
                // the user identity returned by the external identity provider.
                branch.UseCookieAuthentication(options => {
                    options.AutomaticAuthentication = true;
                    options.AuthenticationScheme = "ServerCookie";
                    options.CookieName = CookieAuthenticationDefaults.CookiePrefix + "ServerCookie";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                    options.LoginPath = new PathString("/signin");
                });

                branch.UseGoogleAuthentication(options => {
                    options.ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com";
                    options.ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f";
                });

                branch.UseTwitterAuthentication(options => {
                    options.ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g";
                    options.ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI";
                });
            });

#if !DNXCORE50
            app.UseOwinAppBuilder(owin => {
                // Insert a new middleware responsible of setting the Content-Security-Policy header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
                owin.UseCsp(options => options.DefaultSources(configuration => configuration.Self())
                                              .ImageSources(configuration => configuration.Self().CustomSources("*"))
                                              .ScriptSources(configuration => configuration.UnsafeInline())
                                              .StyleSources(configuration => configuration.Self().UnsafeInline()));

                // Insert a new middleware responsible of setting the X-Content-Type-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXContentTypeOptions();

                // Insert a new middleware responsible of setting the X-Frame-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXfo(options => options.Deny());

                // Insert a new middleware responsible of setting the X-Xss-Protection header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXXssProtection(options => options.EnabledWithBlockMode());
            });
#endif

            app.UseOpenIdConnectServer(options => {
                options.AuthenticationScheme = OpenIdConnectDefaults.AuthenticationScheme;

                options.SigningCredentials = credentials;

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;

                options.Provider = new AuthorizationProvider();

                if (string.Equals(environment.RuntimeType, "CoreCLR", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase)) {
                    options.AccessTokenHandler = new UnsafeJwtSecurityTokenHandler();
                    options.IdentityTokenHandler = new UnsafeJwtSecurityTokenHandler();
                }
            });

            app.UseStaticFiles();

            app.UseMvc();

            app.UseWelcomePage();

            using (var database = app.ApplicationServices.GetService<ApplicationContext>()) {
                database.Applications.Add(new Application {
                    ApplicationID = "myClient",
                    DisplayName = "My client application",
                    RedirectUri = "http://localhost:37045/index.html",
                    LogoutRedirectUri = "http://localhost:37045/index.html",
                    Secret = "secret_secret_secret"
                });

                database.SaveChanges();
            }
        }

        // Note: in a real world app, you'd probably prefer storing the X.509 certificate
        // in the user or machine store. To keep this sample easy to use, the certificate
        // is extracted from the Certificate.cer/pfx file embedded in this assembly.
        private static X509Certificate2 LoadCertificate(IRuntimeEnvironment environment) {
            if (string.Equals(environment.RuntimeType, "CoreCLR", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase)) {
                using (var stream = typeof(Startup).GetTypeInfo().Assembly.GetManifestResourceStream("Mvc.Server.Certificate.cer"))
                using (var buffer = new MemoryStream()) {
                    stream.CopyTo(buffer);
                    buffer.Flush();

                    return new X509Certificate2(buffer.ToArray()) {
                        PrivateKey = LoadPrivateKey(environment)
                    };
                }
            }

            using (var stream = typeof(Startup).GetTypeInfo().Assembly.GetManifestResourceStream("Mvc.Server.Certificate.pfx"))
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);
                buffer.Flush();

                return new X509Certificate2(buffer.ToArray(), "Owin.Security.OpenIdConnect.Server");
            }
        }

        // Note: CoreCLR doesn't support .pfx files yet. To work around this limitation, the private key
        // is stored in a different - and totally unprotected/unencrypted - .keys file and attached to the
        // X509Certificate2 instance in LoadCertificate: NEVER do that in a real world application.
        // See https://github.com/dotnet/corefx/issues/424
        private static RSA LoadPrivateKey(IRuntimeEnvironment environment) {
            using (var stream = typeof(Startup).GetTypeInfo().Assembly.GetManifestResourceStream("Mvc.Server.Certificate.keys"))
            using (var reader = new StreamReader(stream)) {
                // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/179
                var key = string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase) ?
                    new RSACryptoServiceProvider(new CspParameters { ProviderType = 24 }) :
                    new RSACryptoServiceProvider();
                
                key.ImportParameters(new RSAParameters {
                    D = Convert.FromBase64String(reader.ReadLine()),
                    DP = Convert.FromBase64String(reader.ReadLine()),
                    DQ = Convert.FromBase64String(reader.ReadLine()),
                    Exponent = Convert.FromBase64String(reader.ReadLine()),
                    InverseQ = Convert.FromBase64String(reader.ReadLine()),
                    Modulus = Convert.FromBase64String(reader.ReadLine()),
                    P = Convert.FromBase64String(reader.ReadLine()),
                    Q = Convert.FromBase64String(reader.ReadLine())
                });

                return key;
            }
        }

        // There's currently a bug on CoreCLR that prevents ValidateSignature from working correctly.
        // To work around this bug, signature validation is temporarily disabled: of course,
        // NEVER do that in a real world application as it opens a huge security hole.
        // See https://github.com/aspnet/Security/issues/223
        private class UnsafeJwtSecurityTokenHandler : JwtSecurityTokenHandler {
            protected override JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters) {
                return ReadToken(token) as JwtSecurityToken;
            }
        }
    }
}