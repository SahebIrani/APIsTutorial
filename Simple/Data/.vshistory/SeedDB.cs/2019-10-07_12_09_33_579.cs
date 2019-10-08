using System;
using System.Linq;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

using Simple.Models;

namespace Simple.Data
{
    public class SeedDB
    {
        public static void Initialize(IServiceProvider serviceProvider)
        {
            var context = serviceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            //context.Database.EnsureDeleted();
            context.Database.EnsureCreated();
            if (!context.Users.Any())
            {
                ApplicationUser user = new ApplicationUser()
                {
                    UserName = "SinjulMSBH",
                    Email = "sinjul.msbh@yahoo.com",
                    SecurityStamp = Guid.NewGuid().ToString(),
                };

                ApplicationUser user2 = new ApplicationUser()
                {
                    UserName = "JackSlater",
                    Email = "jackslater.irani@gmail.com",
                    SecurityStamp = Guid.NewGuid().ToString(),
                };

                userManager.CreateAsync(user, "Sinjul_4");
                userManager.CreateAsync(user2, "Sinjul_4");
            }
        }
    }
}
