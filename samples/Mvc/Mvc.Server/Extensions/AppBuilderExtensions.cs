#if ASPNET50
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.Owin.Builder;
using Microsoft.Owin.BuilderProperties;
using Owin;

namespace Mvc.Server.Extensions {
    using AppFunc = Func<IDictionary<string, object>, Task>;

    public static class AppBuilderExtensions {
        public static IApplicationBuilder UseOwinAppBuilder(this IApplicationBuilder app, Action<IAppBuilder> action) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (action == null) {
                throw new ArgumentNullException(nameof(action));
            }

            return app.UseOwin(setup => setup(next => {
                var builder = new AppBuilder();
                var lifetime = (IApplicationLifetime) app.ApplicationServices.GetService(typeof(IApplicationLifetime));

                var properties = new AppProperties(builder.Properties);
                properties.AppName = app.Server.Name;
                properties.OnAppDisposing = lifetime.ApplicationStopping;
                properties.DefaultApp = next;

                action(builder);

                return builder.Build<AppFunc>();
            }));
        }
    }
}
#endif