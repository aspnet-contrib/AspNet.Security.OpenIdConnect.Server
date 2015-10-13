using System;
using Xunit.Sdk;

namespace Owin.Security.OpenIdConnect.Server.Tests {

    [TraitDiscoverer("Owin.Security.OpenIdConnect.Server.Tests.ActiveIssueDiscoverer", "Owin.Security.OpenIdConnect.Server.Tests")]
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public class ActiveIssueAttribute : Attribute, ITraitAttribute {
        public ActiveIssueAttribute(string issue) { }
        public ActiveIssueAttribute(int issueNumber) { }
    }
}