using System.Security.Claims;
using Nancy.Security;

namespace Nancy.Client.Modules {
    public class HomeModule : NancyModule {
        public HomeModule() {
            Get["/"] = parameters => {
                ClaimsPrincipal principal = Context.GetMSOwinUser();

                // Determine whether the user agent has been successfully authenticated
                // by the cookies middleware (configured with AuthenticationMode.Active in Startup.cs)
                if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated) {
                    principal = null;
                }

                return View["home.cshtml", principal];
            };
        }
    }
}