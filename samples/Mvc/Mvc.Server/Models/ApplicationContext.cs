using Microsoft.EntityFrameworkCore;

namespace Mvc.Server.Models {
    public class ApplicationContext : DbContext {
        public DbSet<Application> Applications { get; set; }
    }
}