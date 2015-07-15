using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Owin.Security.OpenIdConnect.Server.Tests {

    public class ActiveIssueDiscoverer : ITraitDiscoverer {
        /// <summary>
        ///     Gets the trait values from the Category attribute.
        /// </summary>
        /// <param name="traitAttribute">The trait attribute containing the trait values.</param>
        /// <returns>The trait values.</returns>
        public IEnumerable<KeyValuePair<string, string>> GetTraits(IAttributeInfo traitAttribute) {
            var ctorArgs = traitAttribute.GetConstructorArguments();
            Debug.Assert(ctorArgs.Any());

            yield return new KeyValuePair<string, string>("activeissue", ctorArgs.First().ToString());
        }
    }
}