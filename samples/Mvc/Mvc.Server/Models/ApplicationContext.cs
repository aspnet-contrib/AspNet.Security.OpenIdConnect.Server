using System.Data.Entity;

namespace Mvc.Server.Models {
    public class ApplicationContext : DbContext {
        static ApplicationContext() {
            Database.SetInitializer(new ApplicationContextInitializer());
        }

        public ApplicationContext()
            : base("ApplicationContextMvc") {
        }

        public IDbSet<Application> Applications { get; set; }
        public IDbSet<Nonce> Nonces { get; set; }
    }
}