using System.ComponentModel.DataAnnotations;

namespace ZCATSS_Tracker.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string? Password { get; set; }

        //[Display(Name = "Remember me?")]
        //public bool RememberMe { get; set; } = false;

    }
}