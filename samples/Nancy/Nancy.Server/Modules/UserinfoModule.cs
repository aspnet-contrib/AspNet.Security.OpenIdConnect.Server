using System.Security.Claims;
using Nancy.Security;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server.Modules {
    public class UserinfoModule : NancyModule {
        public UserinfoModule() {
            Get["/connect/userinfo", runAsync: true] = async (parameters, cancellationToken) => {
                var manager = Context.GetAuthenticationManager();
                if (manager == null) {
                    return HttpStatusCode.InternalServerError;
                }

                var identity = await manager.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationType);
                if (identity == null || !identity.Identity.IsAuthenticated) {
                    manager.Challenge(OpenIdConnectServerDefaults.AuthenticationType);

                    return HttpStatusCode.Unauthorized;
                }

                return Response.AsJson(new {
                    sub = identity.Identity.FindFirst(ClaimTypes.NameIdentifier)?.Value,
                    name = identity.Identity.FindFirst(ClaimTypes.Name)?.Value
                });
            };
        }
    }
}
