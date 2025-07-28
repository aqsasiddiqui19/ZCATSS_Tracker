using System.Security.Claims;

namespace ZCATSS_Tracker.Interface
{
    public interface IJwtTokenValidator
    {
        ClaimsPrincipal ValidateToken(string token);
    }

}
