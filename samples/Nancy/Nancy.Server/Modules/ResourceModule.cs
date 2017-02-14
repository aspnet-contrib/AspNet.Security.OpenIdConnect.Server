using System.Security.Claims;
using Nancy.Security;

namespace Nancy.Server.Modules
{
    public class ResourceModule : NancyModule
    {
        public ResourceModule()
        {
            Get["/api/message"] = parameters =>
            {
                this.RequiresMSOwinAuthentication();

                var principal = Context.GetMSOwinUser();
                if (principal == null)
                {
                    return HttpStatusCode.InternalServerError;
                }

                var identity = principal.Identity as ClaimsIdentity;
                if (identity == null || !identity.IsAuthenticated)
                {
                    return HttpStatusCode.InternalServerError;
                }

                return $"{identity.Name} has been successfully authenticated.";
            };
        }
    }
}
