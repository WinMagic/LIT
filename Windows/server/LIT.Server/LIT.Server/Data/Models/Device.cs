namespace LIT.ServerMVC.Data.Models
{
    public class Device
    {
        public Guid DeviceId { get; set; }
        public required string DeviceName { get; set; }
        public DateTime DateCreated { get; set; }
        public ICollection<KeyRegistration> Keys { get; set; }
    }
}
