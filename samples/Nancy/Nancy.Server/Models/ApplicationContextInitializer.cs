using System.Data.Entity;

namespace Nancy.Server.Models
{
    public class ApplicationContextInitializer : DropCreateDatabaseIfModelChanges<ApplicationContext>
    {
        protected override void Seed(ApplicationContext context)
        {
            // Note: when using the introspection middleware, your resource server
            // MUST be registered as an OAuth2 client and have valid credentials.
            //
            // context.Applications.Add(new Application {
            //     ApplicationID = "resource_server",
            //     DisplayName = "Main resource server",
            //     Secret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd"
            // });

            // Note: these values must match the settings defined in Nancy.Client.
            context.Applications.Add(new Application
            {
                ApplicationID = "myClient",
                DisplayName = "My client application",
                RedirectUri = "http://localhost:56765/oidc",
                LogoutRedirectUri = "http://localhost:56765/",
                Secret = "secret_secret_secret"
            });
        }
    }
}
