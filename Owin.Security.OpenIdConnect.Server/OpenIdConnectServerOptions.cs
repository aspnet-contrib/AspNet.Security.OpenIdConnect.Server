using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;

namespace Microsoft.Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Options class provides information needed to control Authorization Server middleware behavior
    /// </summary>
    public class OpenIdConnectServerOptions : OAuthAuthorizationServerOptions
    {
        public OpenIdConnectServerOptions()
        {
            this.TokenHandler = new JwtSecurityTokenHandler();
            this.ServerClaimsMapper = (claims) => claims;
        }

        public TimeSpan IdTokenExpireTimeSpan { get; set; }
        public string IssuerName { get; set; }
        public Func<IEnumerable<Claim>, IEnumerable<Claim>> ServerClaimsMapper { get; set; }
        public SignatureProvider SignatureProvider { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
        public JwtSecurityTokenHandler TokenHandler { get; set; }
    }
}
