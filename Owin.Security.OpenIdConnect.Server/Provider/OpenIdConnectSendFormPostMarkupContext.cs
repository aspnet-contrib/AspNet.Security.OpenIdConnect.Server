using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Provides context information used when sending markup for implementing 
    /// response_mode=form_post
    /// </summary>
    public class OpenIdConnectSendFormPostMarkupContext : BaseContext
    {
        public OpenIdConnectSendFormPostMarkupContext(
            IOwinContext context,
            IDictionary<string, string> returnParameters,
            String redirectUri)
            : base(context)
        {
            if (returnParameters == null)
            {
                throw new ArgumentNullException("returnParameters");
            }

            if (string.IsNullOrEmpty(redirectUri))
            {
                throw new ArgumentNullException("redirectUri");
            }

            this.ReturnParameters = returnParameters;
            this.RedirectUri = redirectUri;
        }

        /// <summary>
        /// The parameters that should be send to the client
        /// </summary>
        public IDictionary<string, string> ReturnParameters { get; set; }

        /// <summary>
        /// The uri, the form_post should redirect the user to
        /// </summary>
        public string RedirectUri { get; set; }
    }
}
