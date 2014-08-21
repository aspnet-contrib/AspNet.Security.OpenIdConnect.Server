using Nancy.Bootstrapper;
using Nancy.Security;
using Nancy.TinyIoc;

namespace Nancy.Server {
    public class NancyBootstrapper : DefaultNancyBootstrapper {
        protected override void ApplicationStartup(TinyIoCContainer container, IPipelines pipelines) {
            Csrf.Enable(pipelines);

            base.ApplicationStartup(container, pipelines);
        }
    }
}