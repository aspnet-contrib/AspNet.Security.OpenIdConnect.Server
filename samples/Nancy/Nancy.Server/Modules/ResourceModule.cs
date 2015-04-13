using System.Globalization;
using System.Security.Claims;
using Nancy.Security;

namespace Nancy.Server.Modules {
    public class ResourceModule : NancyModule {
        public ResourceModule() {
            Get["/api/message"] = parameters => {
                this.RequiresMSOwinAuthentication();

                var principal = Context.GetMSOwinUser();
                if (principal == null) {
                    return HttpStatusCode.InternalServerError;
                }

                var identity = principal.Identity as ClaimsIdentity;
                if (identity == null || !identity.IsAuthenticated) {
                    return HttpStatusCode.InternalServerError;
                }

                // Note: identity is the ClaimsIdentity representing the resource owner
                // and identity.Actor is the identity corresponding to the client
                // application the access token has been issued to (delegation).
                return string.Format(
                    CultureInfo.InvariantCulture,
                    "{0} has been successfully authenticated via {1}",
                    identity.Name, identity.Actor.Name);
            };
        }
    }
}
