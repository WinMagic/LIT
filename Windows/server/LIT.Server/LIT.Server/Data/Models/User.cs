namespace LIT.ServerMVC.Data.Models
{
    public class User
    {
        public Guid UserId { get; set; }
        public required string UserName { get; set; }
        public required string Password { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public DateTime DateCreated { get; set; }
        public ICollection<KeyRegistration> Keys { get; set; }
        public ICollection<TodoItem> TodoItems { get; set; }
    }
}
