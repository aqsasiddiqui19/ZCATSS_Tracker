using ZCATSS_Tracker.Interface;

namespace ZCATSS_Tracker.Middleware
{

    public class JwtCookieMiddleware
    {
        private readonly RequestDelegate _next;
        //private readonly string _cookieName = "access_token";

        public JwtCookieMiddleware(RequestDelegate next) => 
            _next = next;


        public async Task InvokeAsync(HttpContext context, IJwtTokenValidator jwtValidator)
        {
            var token = context.Request.Cookies["AccessToken"]; // or your custom cookie name

            if (!string.IsNullOrEmpty(token))
            {
                try
                {
                    var principal = jwtValidator.ValidateToken(token);
                    if (principal != null)
                    {
                        context.User = principal;
                    }
                }
                catch (Exception ex)
                {
                    // Log exception if needed
                    Console.WriteLine("JWT validation failed: " + ex.Message);
                }
            }

            await _next(context); // Pass request to next middleware
        }
    }
}


