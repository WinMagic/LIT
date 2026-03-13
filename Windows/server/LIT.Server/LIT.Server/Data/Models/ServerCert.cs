namespace LIT.ServerMVC.Data.Models
{
    public class ServerCert
    {
        public int Index { get; set; }
        public required string Name { get; set; }
        public required byte[] Value { get; set; }
        public required string Thumbprint { get; set; }
        public DateTime DateCreated { get; set; }
    }
}
