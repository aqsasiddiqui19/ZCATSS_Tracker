//using Final_Project.Models;
//using Microsoft.AspNetCore.Identity;

//namespace Final_Project.Helper
//{
//    public static class AdminSeeder
//    {
//        public static async Task SeedAdminUser(IServiceProvider services, IConfiguration configuration)
//        {
//            var userManager = services.GetRequiredService<UserManager<IdentityUser>>();
//            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

//            // Read from configuration
//            var adminEmail = configuration["AdminUser:Email"];
//            var adminUserName = configuration["AdminUser:UserName"];
//            var adminPassword = configuration["AdminUser:Password"];

//            // Validate configuration values
//            if (string.IsNullOrWhiteSpace(adminEmail))
//            {
//                Console.WriteLine("Admin email is missing in configuration.");
//                return;
//            }

//            if (string.IsNullOrWhiteSpace(adminUserName))
//            {
//                Console.WriteLine("Admin username is missing in configuration.");
//                return;
//            }

//            if (string.IsNullOrWhiteSpace(adminPassword))
//            {
//                Console.WriteLine("Admin password is missing in configuration.");
//                return;
//            }

//            // Check if admin user already exists
//            var existingUser = await userManager.FindByEmailAsync(adminEmail);
//            if (existingUser != null)
//            {
//                Console.WriteLine("Admin user already exists.");
//                return;
//            }

//            // Create admin user
//            var adminUser = new IdentityUser
//            {
//                UserName = adminUserName,
//                Email = adminEmail,
//                EmailConfirmed = true,

//            };


//            var user = await userManager.FindByEmailAsync("superadmin@gmail.com");
//            if (user != null)
//            {
//                var token = await userManager.GeneratePasswordResetTokenAsync(user);
//                var results = await userManager.ResetPasswordAsync(user, token, "NewAdminPassword@Admin@123");

//                if (result.Succeeded)
//                {
//                    Console.WriteLine("✅ Admin password changed successfully");
//                }
//                else
//                {
//                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
//                    Console.WriteLine($" Failed to create admin user: {errors}");
//                }
//            }
//        }


//        var result = await userManager.CreateAsync(adminUser, adminPassword);

//            if (result.Succeeded)
//            {
//                Console.WriteLine("Admin user created.");

//                // Create role if it doesn't exist
//                if (!await roleManager.RoleExistsAsync("Admin"))
//                {
//                    await roleManager.CreateAsync(new IdentityRole("Admin"));
//                    Console.WriteLine("Admin role created.");
//                }

//                // Assign role
//                await userManager.AddToRoleAsync(adminUser, "Admin");
//                Console.WriteLine("Admin role assigned to user.");
//            }



//        }
//    }



using ZCATSS_Tracker.Models;
using Microsoft.AspNetCore.Identity;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace ZCATSS_Tracker.Helper
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.DependencyInjection;

    public static class AdminSeeder
    {
        public static async Task SeedAdminUser(IServiceProvider services)
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
            {

                var adminEmail = "superadmin@gmail.com";
                var adminPassword = "admin123A!@D";

                // Check if admin user exists
                var adminUser = await userManager.FindByEmailAsync(adminEmail);
                if (adminUser == null)
                {
                    adminUser = new ApplicationUser
                    {
                        UserName = "admin",
                        Email = adminEmail,
                        EmailConfirmed = true

                    };

                        var result = await userManager.CreateAsync(adminUser, adminPassword);

                        if (!result.Succeeded)
                        {
                            var errorMessages = result.Errors.Select(error => error.Description);
                            var combinedErrorMessage = string.Join(", ", errorMessages);
                            throw new Exception($"Admin user creation failed: {combinedErrorMessage}");
                        }

                        // Ensure the role exists before assigning
                        if (!await roleManager.RoleExistsAsync("Admin"))
                        {
                            await roleManager.CreateAsync(new IdentityRole("Admin"));
                        }

                        //Assign Admin role to the user
                        await userManager.AddToRoleAsync(adminUser, "Admin");

                        // Add custom claim if not exists
                        var claims = await userManager.GetClaimsAsync(adminUser);
                        if (!claims.Any(c => c.Type == "AdminAccess" && c.Value == "True"))
                        {
                            await userManager.AddClaimAsync(adminUser, new Claim("AdminAccess", "True"));
                        }

                        Console.WriteLine("✅ Admin user created and configured.");
                    }
                    else
                    {
                        Console.WriteLine("ℹ️ Admin user already exists.");
                    }

                }
            }
    }
}



