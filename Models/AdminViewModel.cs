using System.ComponentModel.DataAnnotations;

namespace ZCATSS_Tracker.Models
{
    public class AdminViewModel
    {

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters long")]
        [DataType(DataType.Password)]
        public string? Password { get; set; }
        public string? Role { get; set; } = "Admin";
        public bool? IsActive { get; set; } = true;
    }

}
