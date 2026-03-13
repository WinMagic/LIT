namespace LIT.ServerMVC.Data.Models
{
    public class KeyRegistration
    {
        public int KeyRegistrationId { get; set; }
        public Guid UserId { get; set; }
        public Guid DeviceId { get; set; }
        public required byte[] PublicKey { get; set; }
        public int KeyType { get; set; }
        public required string KeyUsage { get; set; }
        public string? Thumbprint { get; set; }
        public DateTime DateCreated { get; set; }
        public DateTime DateModified { get; set; }
        public virtual User User { get; set; }
        public virtual Device Device { get; set; }
    }
}
