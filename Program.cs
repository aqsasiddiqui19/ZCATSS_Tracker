using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Claims;
using System.Text;
using ZCATSS_Tracker.Helper;
using ZCATSS_Tracker.Interface;
using ZCATSS_Tracker.Middleware;
using ZCATSS_Tracker.Models;
using ZCATSS_Tracker.Services;
using ZCATSS_Tracker.TokenValidator;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Con")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

//builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//    .AddCookie(options =>
//    {
//        options.LoginPath = "/Auth/Login";
//        options.AccessDeniedPath = "/Auth/Logout";
//        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
//    });

/// Add Authentication: Cookie + JWT
/// 

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(1); // ?? Short-lived cookie
    options.SlidingExpiration = true;                // No auto-renew
    options.Events.OnValidatePrincipal = context =>
    {
        // Optional: You can manually decode and validate JWT here if needed
        return Task.CompletedTask;
    };
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]
                ?? throw new InvalidOperationException("JWT Key missing"))),

        // Optional but helpful for role-based auth
        RoleClaimType = ClaimTypes.Role
    };
});


//builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//    .AddCookie(); // ?? this registers "Cookies"

//builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddScoped<JwtTokenService>();

builder.Services.AddScoped<IJwtTokenValidator, JwtTokenValidator>();

//builder.Services.AddDefaultIdentity<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
//    .AddRoles<IdentityRole>() // <-- This is the key line
//    .AddEntityFrameworkStores<ApplicationDbContext>();

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// ?? MUST come first: This middleware reads JWT from cookie and sets header
app.UseMiddleware<JwtCookieMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

//Route configuration
app.MapControllerRoute(
    name: "admin",
    pattern: "admin/Dashboard",
    defaults: new { controller = "Admin", action = "Dashboard" });

app.MapControllerRoute(
    name: "recruiter",
    pattern: "recruiter/Dashboard",
    defaults: new { controller = "Recruiter", action = "Dashboard" });


app.MapControllerRoute(
    name: "user",
    pattern: "user/home",
    defaults: new { controller = "User", action = "Home" });

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

//Seed the admin user
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var config = services.GetRequiredService<IConfiguration>();
    await AdminSeeder.SeedAdminUser(services);
}

app.Run();
