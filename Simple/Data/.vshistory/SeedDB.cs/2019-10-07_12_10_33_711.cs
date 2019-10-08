using System;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

using Simple.Models;

namespace Simple.Data
{
    public static class SeedDB
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider)
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

                await userManager.CreateAsync(user, "Sinjul_4");
                await userManager.CreateAsync(user2, "Sinjul_4");
            }
        }
    }
}
