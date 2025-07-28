using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace ZCATSS_Tracker.Models
{

    public class ApplicationUser : IdentityUser
    {

        public string? Accesstoken { get; set; } // optional — mostly for debugging or testing
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
    }

}






