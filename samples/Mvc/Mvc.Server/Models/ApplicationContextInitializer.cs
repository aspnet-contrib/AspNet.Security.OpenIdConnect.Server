using System.Data.Entity;

namespace Mvc.Server.Models {
    public class ApplicationContextInitializer : DropCreateDatabaseIfModelChanges<ApplicationContext> {
        protected override void Seed(ApplicationContext context) {
            // Note: these values must match the settings defined in Mvc.Client.
            context.Applications.Add(new Application {
                ApplicationID = "myClient",
                DisplayName = "My client application",
                RedirectUri = "http://localhost:56854/oidc",
                LogoutRedirectUri = "http://localhost:56854/",
                Secret = "secret_secret_secret"
            });
        }
    }
}