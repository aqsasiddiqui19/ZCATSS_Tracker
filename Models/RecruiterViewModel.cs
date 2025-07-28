using System.ComponentModel.DataAnnotations;

namespace ZCATSS_Tracker.Models
{
    using System.ComponentModel.DataAnnotations;

    public class RecruiterViewModel
    {
        [Required]
        public string UserName { get; set; } = string.Empty;    

        [Required]
        [EmailAddress]
        public string Email { get; set; } =  string.Empty ;

        [Required]
        [DataType(DataType.Password)]
        public string? Password { get; set; }

        [Required]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        [DataType(DataType.Password)]
        public string? ConfirmPassword { get; set; }

        public string Role { get; set; } = "Recruiter";

    }

}
