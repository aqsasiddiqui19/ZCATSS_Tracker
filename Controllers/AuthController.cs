using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ZCATSS_Tracker.Models;
using ZCATSS_Tracker.Services;


namespace ZCATSS_Tracker.Controllers
{
    public class AuthController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JwtTokenService _jwtTokenService;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;

        public AuthController(UserManager<ApplicationUser> userManager,RoleManager<IdentityRole> roleManager,   
            IConfiguration config,
            SignInManager<ApplicationUser> signInManager,
            JwtTokenService jwtTokenService)
        {
            _userManager = userManager;
            //_roleManager = roleManager;
            _config = config;
            _roleManager = roleManager; 
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
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
                Email = model.Email,
             };


            //Create User
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new { message = "Registration failed.", errors });
            }

            // Ensure the role exists
            if (!await _roleManager.RoleExistsAsync("User"))
            {
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }

            // Assign the role to the user
            if (!await _userManager.IsInRoleAsync(user, "User"))
            {
                await _userManager.AddToRoleAsync(user, "User");
            }

            //Add Custom Claim (fixed typo 'UserAccesss' → 'UserAccess')
            await _userManager.AddClaimAsync(user, new Claim("UserAccess", "True"));

            //Redirect
            return RedirectToAction("login", "Auth");
        }


        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return Unauthorized("User not found");

            if (string.IsNullOrWhiteSpace(model.Password))
            {
                return BadRequest(new { message = "Password is required." });
            }

            var result = await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: false);

            if (!result.Succeeded)
                return Unauthorized("Invalid login attempt");

            // 1. Get user roles
            var roles = await _userManager.GetRolesAsync(user);

            // 1. Get user roles
            //var roles = await _userManager.GetRolesAsync(user);

            // 2. Create claims
            var claims = new List<Claim>
                {
                  new Claim(ClaimTypes.Name, user.UserName),
                  new Claim(ClaimTypes.NameIdentifier, user.Id),

                  };


            // Add roles only once using ClaimTypes.Role
            foreach (var role in roles.Distinct())
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

     
            //Create identity and sign in via cookie
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);


            // Optional: Save JWTs if you still need them for APIs
            var accessToken = _jwtTokenService.GenerateAccessToken(user, roles, new List<Claim>());
            var refreshToken = _jwtTokenService.GenerateRefreshToken();

            user.Accesstoken = accessToken;
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);

            Response.Cookies.Append("AccessToken", accessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(1)
            });

            Response.Cookies.Append("RefreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            // Get roles
            //var roles = await _userManager.GetRolesAsync(user);

            // Example: If user has no role yet, you can assign one manually
            if (!roles.Any())
            {
                await _userManager.AddToRoleAsync(user, "User"); // Or whatever default
                await _signInManager.SignOutAsync();              // Refresh cookie
                await _signInManager.SignInAsync(user, isPersistent: false);
                roles = await _userManager.GetRolesAsync(user);   // Get updated roles
            }

            // Redirect based on updated role
            if (roles.Contains("Admin"))
            {
                return RedirectToAction("Dashboard", "Admin");
            }
            else if (roles.Contains("Recruiter"))
            {
                return RedirectToAction("Dashboard", "Recruiter");
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }

        }


        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            // 🔐 Sign out from Identity & clear auth cookie
            await _signInManager.SignOutAsync();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // ❌ Delete AccessToken and RefreshToken cookies if they exist
            if (Request.Cookies.ContainsKey("AccessToken"))
                Response.Cookies.Delete("AccessToken");

            if (Request.Cookies.ContainsKey("RefreshToken"))
                Response.Cookies.Delete("RefreshToken");

            //Redirect to Login
            return RedirectToAction("Login", "Auth");
        }



    }
}