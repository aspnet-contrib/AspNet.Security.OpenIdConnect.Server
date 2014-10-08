using System;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;
using Owin;

namespace Mvc.Server.Extensions {
    public class OpenIdConnectResponseBinder : IModelBinder {
        public object BindModel(ControllerContext controllerContext, ModelBindingContext bindingContext) {
            if (controllerContext == null) {
                throw new ArgumentNullException("controllerContext");
            }

            IOwinContext context = controllerContext.HttpContext.GetOwinContext();
            if (context == null) {
                throw new NotSupportedException("An OWIN context cannot be extracted from ControllerContext.HttpContext");
            }

            return context.GetOpenIdConnectResponse();
        }
    }
}