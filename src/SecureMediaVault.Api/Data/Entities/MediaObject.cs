using System.ComponentModel.DataAnnotations;

namespace SecureMediaVault.Api.Data.Entities
{
    public class MediaObject
    {
        [Key] 
        public Guid Id { get; set; } = Guid.NewGuid();

        public string FileName { get; set; } = string.Empty;
        public string ContentType { get; set; } = string.Empty;
        public long FileSize { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string StorageKey { get; set; } = string.Empty; 


        public byte[] EncryptedDek { get; set; } = Array.Empty<byte>();

        public Guid AppUserId { get; set; } 
        public AppUser? AppUser { get; set; } 
    }
}