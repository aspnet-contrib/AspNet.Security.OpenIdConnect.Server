using System.Collections.Generic;
using Microsoft.AspNet.Http.Authentication;

namespace Mvc.Server.Models
{
    public class AuthenticationModel
    {
        public string Provider { get; set; }
        public string ReturnUrl { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public IEnumerable<AuthenticationDescription> AuthenticationDescriptions { get; set; }
    }
}