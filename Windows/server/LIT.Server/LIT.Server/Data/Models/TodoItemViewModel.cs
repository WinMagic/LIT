namespace LIT.ServerMVC.Data.Models
{
    public class TodoItemViewModel
    {
        public required string Title { get; set; }
        public string? Description { get; set; }
        public bool IsCompleted { get; set; }

    }
}
