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
using ROPC.Models;
using Microsoft.Data.Entity;
using Microsoft.AspNet.Identity.EntityFramework;

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

        public void Configure(IApplicationBuilder app)
        {
            app.UseErrorPage();

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync("Hello World!");
            });
        }
    }
}
