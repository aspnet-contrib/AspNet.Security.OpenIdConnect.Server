using System.ComponentModel.DataAnnotations;

namespace Nancy.Server.Models
{
    public class Application
    {
        [Key]
        public string ApplicationID { get; set; }
        public string DisplayName { get; set; }
        public string RedirectUri { get; set; }
        public string LogoutRedirectUri { get; set; }
        public string Secret { get; set; }
    }
}
