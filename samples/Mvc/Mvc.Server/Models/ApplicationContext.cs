using Microsoft.Data.Entity;

namespace Mvc.Server.Models {
    public class ApplicationContext : DbContext {
        public DbSet<Application> Applications { get; set; }
        public DbSet<Nonce> Nonces { get; set; }
    }
}