using System;
using System.Security.Claims;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Routing;

namespace Mvc.Server {
    public class Global : HttpApplication {
        protected void Application_Start(object sender, EventArgs e) {
            RouteTable.Routes.MapMvcAttributeRoutes();

            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;
        }
    }
}