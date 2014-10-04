using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace Mvc.Client {
    public class Global : HttpApplication {
        protected void Application_Start(object sender, EventArgs e) {
            RouteTable.Routes.MapMvcAttributeRoutes();
        }
    }
}