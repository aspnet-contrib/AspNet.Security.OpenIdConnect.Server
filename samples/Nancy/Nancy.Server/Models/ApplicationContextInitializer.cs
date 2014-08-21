using System.Data.Entity;

namespace Nancy.Server.Models {
    public class ApplicationContextInitializer : DropCreateDatabaseIfModelChanges<ApplicationContext> {
        protected override void Seed(ApplicationContext context) {
            // Note: these values must match the settings defined in Nancy.Client.
            context.Applications.Add(new Application {
                ApplicationID = "myClient",
                DisplayName = "My client application",
                RedirectUri = "http://localhost:56765/oidc",
                Secret = "secret_secret_secret"
            });
        }
    }
}