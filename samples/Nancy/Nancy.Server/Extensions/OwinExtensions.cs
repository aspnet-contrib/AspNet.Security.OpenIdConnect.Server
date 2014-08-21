using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin.Security;

namespace Nancy.Server.Extensions {
    public static class OwinExtensions {
        public static IEnumerable<AuthenticationDescription> GetExternalProviders(this IAuthenticationManager manager) {
            if (manager == null) {
                throw new ArgumentNullException("manager");
            }

            return from description in manager.GetAuthenticationTypes()
                   where !string.IsNullOrWhiteSpace(description.Caption)
                   select description;
        }

        public static bool IsProviderSupported(this IAuthenticationManager manager, string provider) {
            if (manager == null) {
                throw new ArgumentNullException("manager");
            }

            return (from description in manager.GetExternalProviders()
                    where string.Equals(description.AuthenticationType, provider, StringComparison.OrdinalIgnoreCase)
                    select description).Any();
        }
    }
}