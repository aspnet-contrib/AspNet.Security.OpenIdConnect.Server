
using AspNet.Security.OpenIdConnect.Server;
using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Hosting;
using Microsoft.Data.Entity;
using Microsoft.Framework.ConfigurationModel;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Runtime;

using ResourceOwnerPasswordFlow.Providers;
using ResourceOwnerPasswordFlow.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity;

/// <summary>
/// Configure the resource owner password credential flow. 
/// 1. The Relying Party sends a request to the Identity Provider.
/// 2. The Identity Provider responds with an Access Token. 
/// 3. The Relying Party saves that Access Token. 
/// 4. The Relying Party sends a request (with the Access Token) to the Resource Server. 
/// 5. The Resource Server validates the Access Token.
/// 6. If it's valid, the Resource Server responds with the requested resources.
/// </summary>


namespace ResourceOwnerPasswordFlow
{
    public class Startup
    {
        public IConfiguration Config { get; set; }

        public Startup(IHostingEnvironment hostEnv, IApplicationEnvironment appEnv)
        {
            // When running in a different environment than the localhost,
            // be sure to update either config.json or environmental variables
            // with appropriate OAuth and OpenId configuration values
            Config = new Configuration(appEnv.ApplicationBasePath)
                .AddJsonFile("config.json")
                .AddEnvironmentVariables();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();
            services.AddCaching();

            // entity framework
            services
                .AddEntityFramework()
                .AddInMemoryDatabase()
                .AddDbContext<ApplicationContext>(options =>
                {
                    options.UseInMemoryDatabase(persist: true);
                });

            // identity
            services
                .AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationContext>()
                .AddDefaultTokenProviders(); // What does this do? 
        }

        public void Configure(IApplicationBuilder app, IRuntimeEnvironment environment, IServiceProvider serviceProvider)
        {
            // HACK: for Azure web apps, 
            // the try-catch block lets us see errors that occur during configuration
            try
            {
                app.UseErrorPage();
                app.UseRuntimeInfoPage();

                // ASP.NET Identity
                app.UseIdentity();
                CreateAdminUser(serviceProvider);

                // Allow serving of .html files in wwwroot
                app.UseStaticFiles();

                // Add a new middleware validating access tokens issued by the server.
                // This middleware is associated with the Resource Server
                app.UseOAuthBearerAuthentication(options =>
                {
                    options.AutomaticAuthentication = true;
                    options.Authority = Config.Get("OAuth:Authority");
                    options.Audience = Config.Get("OAuth:Audience");

                    // if the audience is null or empty, then don't validate it
                    options.TokenValidationParameters.ValidateAudience = Config.Get("OAuth:Audience") != null;
                });

                // Add a new middleware issuing tokens.
                // This middleware is associated with the Identity Provider            
                var credentials = CreateSigningCredentials();
                app.UseOpenIdConnectServer(options =>
                {
                    options.Issuer = Config.Get("OpenId:Issuer") != null ? new Uri(Config.Get("OpenId:Issuer")) : null;
                    options.AllowInsecureHttp = true;
                    options.AuthorizationEndpointPath = PathString.Empty; // Tokens are avaiable by default at ~/connect/token
                    options.SigningCredentials = credentials;
                    options.AuthenticationScheme = OpenIdConnectDefaults.AuthenticationScheme;

                    // is this the right way to inject a user manager into the Authorization Provider?
                    var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
                    options.Provider = new AuthorizationProvider(userManager);
                });
            }
            catch (Exception ex)
            {
                app.Run(async (context) =>
                {
                    await context.Response.WriteAsync(ex.ToString());
                });
            }

            // Run on each request
            app.Run(async (context) =>
            {
                if (context.Request.Path.Value.Contains("my-resource-server"))
                {
                    //
                    // serve the resource server
                    //

                    var authenticated = context.User.Identity.IsAuthenticated;
                    var name = context.User.Identity.Name;

                    var builder = new StringBuilder();

                    builder.Append("<h2>General Info</h2>");

                    builder.AppendFormat("<p>Time: {0}</p>", DateTime.Now.ToString());
                    builder.AppendFormat("<p>Environment: {0}</p>", environment.RuntimeType);
                    builder.AppendFormat("<p>IsAuthenticated: {0}</p>", context.User.Identity.IsAuthenticated);

                    if (context.User.Identity.IsAuthenticated)
                    {
                        //
                        // serve protected resources 
                        // 

                        builder.Append("<h2>Secure Resources</h2>");
                        builder.AppendFormat("<p>User Name: {0}</p>", context.User.Identity.Name);

                        builder.Append("<h2>User Claims</h2>");
                        builder.Append("<dl>");
                        foreach (var claim in context.User.Claims)
                        {
                            builder.AppendFormat("<dt>{0}</dt><dd>{1}</dd>", claim.Type, claim.Value);
                        }
                    }

                    await context.Response.WriteAsync(builder.ToString());
                }
                else
                {
                    //
                    // serve the relying party
                    //

                    context.Response.Redirect("relying-party.html");
                }
            });
        }

        private SigningCredentials CreateSigningCredentials()
        {
            var certificate = LoadCertificate();
            var key = new X509SecurityKey(certificate);

            var credentials = new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest);

            return credentials;
        }

        private X509Certificate2 LoadCertificate()
        {
            var resourceName = "ResourceOwnerPasswordFlow.Certificate.pfx";
            using (var stream = this.GetType()
                .Assembly
                .GetManifestResourceStream(resourceName))

            using (var buffer = new MemoryStream())
            {
                stream.CopyTo(buffer);
                buffer.Flush();

                // azure web apps require `MachineKeySet` for this to work
                return new X509Certificate2(
                    buffer.ToArray(),
                    "Owin.Security.OpenIdConnect.Server",
                    X509KeyStorageFlags.MachineKeySet);
            }
        }

        private void CreateAdminUser(IServiceProvider serviceProvider)
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

                // should we use `.Result` or `await`
                // I need to learn more about async

                var admin = userManager.FindByNameAsync(adminName).Result;
                if (admin == null)
                {
                    admin = new IdentityUser { UserName = adminName };
                    userManager.CreateAsync(admin, adminPassword);
                }

                var developer = userManager.FindByNameAsync(developerName).Result;
                if (developer == null)
                {
                    developer = new IdentityUser { UserName = developerName };
                    userManager.CreateAsync(developer, developerPassword);
                }

                if (!roleManager.RoleExistsAsync(adminRole).Result)
                {
                    roleManager.CreateAsync(new IdentityRole(adminRole));
                }

                if (!roleManager.RoleExistsAsync(developerRole).Result)
                {
                    roleManager.CreateAsync(new IdentityRole(developerRole));
                }

                userManager.AddToRoleAsync(admin, adminRole);
                userManager.AddToRoleAsync(developer, adminRole);
                userManager.AddToRoleAsync(developer, developerRole);
            }
        }
    }
}
