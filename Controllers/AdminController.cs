using ZCATSS_Tracker.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization.Policy;



namespace ZCATSS_Tracker.Controllers
{
    public class AdminController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        //[Authorize(Policy = "Admin")]
        public IActionResult Dashboard()
        {
            return View();
        }


        public IActionResult CreateRecruiter()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> CreateRecruiter(RecruiterViewModel model)
        {
            // Basic validation checks
            if (!ModelState.IsValid)
            {
                return BadRequest(new { message = "Invalid data provided." });
            }

            if (string.IsNullOrWhiteSpace(model.UserName) || model.UserName.Trim().ToLower() == "string")
            {
                return BadRequest(new { message = "Username cannot be 'string' or empty." });
            }

            if (string.IsNullOrWhiteSpace(model.Password))
            {
                return BadRequest(new { message = "Password is required." });
            }

            //Create User Object
            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email
              
            };

            // Create User
            var createResult = await _userManager.CreateAsync(user, model.Password);

            if (!createResult.Succeeded)
            {
                var errors = createResult.Errors.Select(e => e.Description).ToList();
                return BadRequest(new { message = "Recruiter creation failed.", errors });
            }

            // Ensure the role exists
            if (!await _roleManager.RoleExistsAsync("Recruiter"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Recruiter"));
            }

            // Assign the role to the user
            if (!await _userManager.IsInRoleAsync(user, "Recruiter"))
            {
                await _userManager.AddToRoleAsync(user, "Recruiter");
            }

            await _userManager.AddClaimAsync(user, new Claim("RecruiterAccess", "True"));


            //Redirect to dashboard upon successful creation.
            return RedirectToAction("dashboard", "Admin");
        }
    }

}
