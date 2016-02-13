

using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ResourceOwnerPasswordFlow.Models
{
    public class ApplicationContext : IdentityDbContext<IdentityUser>
    {
    }
}