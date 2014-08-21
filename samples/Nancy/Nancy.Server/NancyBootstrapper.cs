using Nancy.Bootstrapper;
using Nancy.Security;
using Nancy.TinyIoc;

namespace Nancy.Server {
    public class NancyBootstrapper : DefaultNancyBootstrapper {
        protected override void ApplicationStartup(TinyIoCContainer container, IPipelines pipelines) {
            // Enable CSRF protection at the pipeline level
            // to be able to use it in AuthorizationModule.cs
            Csrf.Enable(pipelines);

            base.ApplicationStartup(container, pipelines);
        }
    }
}