using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Owin.Security.Infrastructure;
using System.Collections.Concurrent;

namespace SampleOpenIdConnectServer {
    /// <summary>
    /// A very simple AuthenticationTokenProvider for testing-scenarios. 
    /// This implementation is not intended to be used within production-code!
    /// </summary>
    public class TestAuthenticationTokenProvider : AuthenticationTokenProvider {
        private ConcurrentDictionary<string, string> keys = new ConcurrentDictionary<string, string>();

        public override void Create(AuthenticationTokenCreateContext context) {
            string token = Guid.NewGuid().ToString();
            keys[token] = context.SerializeTicket();
            context.SetToken(token);
        }

        public override void Receive(AuthenticationTokenReceiveContext context) {
            string ticket;
            if (keys.TryRemove(context.Token, out ticket)) {
                context.DeserializeTicket(ticket);
            }
        }

    }

}
