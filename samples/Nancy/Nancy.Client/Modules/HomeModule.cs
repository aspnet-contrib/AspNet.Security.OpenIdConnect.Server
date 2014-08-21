using System.Security.Claims;
using Nancy.Security;

namespace Nancy.Client.Modules {
    public class HomeModule : NancyModule {
        public HomeModule() {
            Get["/"] = parameters => {
                ClaimsPrincipal principal = Context.GetMSOwinUser();
                if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated) {
                    principal = null;
                }

                return View["home.cshtml", principal];
            };
        }
    }
}