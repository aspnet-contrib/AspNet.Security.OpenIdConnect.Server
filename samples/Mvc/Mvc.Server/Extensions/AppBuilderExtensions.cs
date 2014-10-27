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
    using BuildFunc = Action<Func<Func<IDictionary<string, object>, Task>,
                                  Func<IDictionary<string, object>, Task>>>;

    public static class AppBuilderExtensions {
        public static void UseOwinAppBuilder(this IApplicationBuilder app, Action<IAppBuilder> configuration) {
            BuildFunc buildFunc = app.UseOwin();

            buildFunc(next => {
                var builder = new AppBuilder();
                var lifetime = (IApplicationLifetime) app.ApplicationServices.GetService(typeof(IApplicationLifetime));

                var properties = new AppProperties(builder.Properties);
                properties.AppName = app.Server.Name;
                properties.OnAppDisposing = lifetime.ApplicationStopping;
                properties.DefaultApp = next;

                configuration(builder);

                AppFunc appFunc = (AppFunc) builder.Build(typeof(AppFunc));

                return environment => appFunc.Invoke(environment);
            });
        }
    }
}
#endif