namespace LIT.ServerMVC.Data.Models
{
    public class TodoItem
    {
        public int Id { get; set; }
        public required string Title { get; set; }
        public string? Description { get; set; }
        public bool IsCompleted { get; set; }
        public Guid UserId { get; set; }
        public DateTime DateCreated { get; set; }
        public virtual User User { get; set; }
    }
}
