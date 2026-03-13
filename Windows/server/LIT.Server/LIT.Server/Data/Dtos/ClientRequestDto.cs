namespace LIT.ServerMVC.Data.Dtos
{
    public class ClientRequestDto
    {
        public string? Request { get; set; }
        public string? KeyUsage { get; set; }
        public int? KeyType { get; set; }
        public string? PubKey { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? DeviceName { get; set; }
    }

    public class ClientRequestResponseDto
    {
        public string? Status { get; set; }
        public string? Message { get; set; }
        public byte[]? Certificate { get; set; }
    }
}
