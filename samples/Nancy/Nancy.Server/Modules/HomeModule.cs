namespace Nancy.Server.Modules
{
    public class HomeModule : NancyModule
    {
        public HomeModule()
        {
            Get["/"] = parameters =>
            {
                return "OpenID Connect server started.";
            };
        }
    }
}
