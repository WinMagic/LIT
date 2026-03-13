using System.ComponentModel.DataAnnotations;

namespace LIT.ServerMVC.Data.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage ="Username is required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
