using System.Data.Entity;

namespace Nancy.Server.Models
{
    public class ApplicationContext : DbContext
    {
        static ApplicationContext()
        {
            Database.SetInitializer(new ApplicationContextInitializer());
        }

        public ApplicationContext()
            : base("ApplicationContext")
        {
        }

        public IDbSet<Application> Applications { get; set; }
    }
}
