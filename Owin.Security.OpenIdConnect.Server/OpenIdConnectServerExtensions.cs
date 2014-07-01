using Microsoft.Owin.Security.OpenIdConnect.Server;

namespace Owin
{
    public static class OpenIdConnectServerExtensions
    {
        /// <summary>
        /// Adds Open Id Connect Authorization Server capabilities to an OWIN web application. This middleware
        /// performs the request processing for the Authorize and Token endpoints defined by the OpenId Connect specification.
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="options">Options which control the behavior of the Authorization Server.</param>
        /// <returns>The application builder</returns>
        public static IAppBuilder UseOpenIdConnectAuthorizationServer(this IAppBuilder app, OpenIdConnectServerOptions options)
        {
            return app.Use(typeof(OpenIdConnectServerMiddleware), app, options);
        }
    }
}
