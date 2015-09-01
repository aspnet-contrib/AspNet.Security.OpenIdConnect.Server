using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Configuration;
using Microsoft.AspNet.Hosting;
using Microsoft.Dnx.Runtime;
using Microsoft.Data.Entity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity;
using AspNet.Security.OpenIdConnect.Server;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Reflection;
using ROPC.Models;
using ROPC.Providers;

namespace ROPC
{
    public class Startup
    {
        public IConfiguration Config { get; set; }

        public Startup(IHostingEnvironment hostEnv, IApplicationEnvironment appEnv)
        {
            // When running in a different environment than the localhost,
            // be sure to update either config.json or environmental variables
            // with appropriate OAuth and OpenId configuration values
            var builder = new ConfigurationBuilder(appEnv.ApplicationBasePath);
            builder.AddJsonFile("config.json");
            builder.AddEnvironmentVariables();
            Config = builder.Build();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();
            services.AddCaching();

            services
                .AddEntityFramework()
                .AddInMemoryDatabase()
                .AddDbContext<ApplicationContext>(options =>
                {
                    options.UseInMemoryDatabase(persist:true);
                });

            services
                .AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationContext>();
        }

        public void Configure(
            IApplicationBuilder app,
            IServiceProvider serviceProvider,
            IRuntimeEnvironment environment)
        {
            // Diagnostics
            app.UseErrorPage();
            app.UseRuntimeInfoPage();

            // Allow serving of .html files in wwwroot
            app.UseStaticFiles();

            // ASP.NET Identity
            app.UseIdentity();
            CreateUsersAsync(serviceProvider)
                .GetAwaiter()
                .GetResult();

            // Add a new middleware validating access tokens issued by the server.
            // This middleware is associated with the Resource Server
            app.UseOAuthBearerAuthentication(options =>
            {
                options.AutomaticAuthentication = true;
                options.Authority = Config["OAuth:Authority"];
                options.Audience = Config["OAuth:Audience"];

                // if the audience is null or empty, then don't validate it
                options.TokenValidationParameters.ValidateAudience = Config["OAuth:Audience"] != null;
            });

            // Add a new middleware issuing tokens.
            // This middleware is associated with the Identity Provider            
            app.UseOpenIdConnectServer(options =>
            {
                options.Issuer = Config["OpenId:Issuer"] != null ? new Uri(Config["OpenId:Issuer"]) : null;
                options.AuthorizationEndpointPath = PathString.Empty; // Tokens are avaiable by default at ~/connect/token

                options.AllowInsecureHttp = true;
                options.AuthenticationScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.Provider = new AuthorizationProvider();

                // There's currently a bug in System.IdentityModel.Tokens that prevents using X509 certificates on Mono.
                // To work around this bug, a new in-memory RSA key is generated each time this app is started.
                // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/179
                if (string.Equals(environment.RuntimeType, "Mono", StringComparison.OrdinalIgnoreCase))
                {
                    // mono
                    var rsaCryptoServiceProvider = new RSACryptoServiceProvider(2048);
                    var rsaParameters = rsaCryptoServiceProvider.ExportParameters(includePrivateParameters: true);
                    options.UseKey(new RsaSecurityKey(rsaParameters));
                }
                else
                {
                    // not mono
                    options.UseCertificate(
                        assembly: typeof(Startup).GetTypeInfo().Assembly,
                        resource: "ROPC.Certificate.pfx",
                        password: "Owin.Security.OpenIdConnect.Server");
                }

            });

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync("Hello World!");
            });
        }

        #region Private Methods

        private async Task CreateUsersAsync(IServiceProvider serviceProvider)
        {
            // create admin user
            bool created = false;
            var db = serviceProvider.GetRequiredService<ApplicationContext>();

            created = db.Database.EnsureCreated();
            if (created)
            {
                const string adminRole = "Administrator";
                const string adminName = "Dave";
                const string adminPassword = "Testing123!";

                const string developerRole = "Developer";
                const string developerName = "Shaun";
                const string developerPassword = adminPassword;

                var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
                var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                var admin = await userManager.FindByNameAsync(adminName);
                if (admin == null)
                {
                    admin = new IdentityUser { UserName = adminName };
                    await userManager.CreateAsync(admin, adminPassword);
                }

                var developer = await userManager.FindByNameAsync(developerName);
                if (developer == null)
                {
                    developer = new IdentityUser { UserName = developerName };
                    await userManager.CreateAsync(developer, developerPassword);
                }

                if (!await roleManager.RoleExistsAsync(adminRole))
                {
                    await roleManager.CreateAsync(new IdentityRole(adminRole));
                }

                if (!await roleManager.RoleExistsAsync(developerRole))
                {
                    await roleManager.CreateAsync(new IdentityRole(developerRole));
                }

                await userManager.AddToRoleAsync(admin, adminRole);
                await userManager.AddToRoleAsync(developer, adminRole);
                await userManager.AddToRoleAsync(developer, developerRole);
            }
        }

        #endregion
    }
}
