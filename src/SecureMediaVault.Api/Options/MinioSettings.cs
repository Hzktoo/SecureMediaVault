namespace SecureMediaVault.Api.Options;

public class MinioSettings
{
    public const string SectionName = "Minio"; 

    public string Endpoint { get; set; } = string.Empty;
    public string AccessKey { get; set; } = string.Empty;
    public string SecretKey { get; set; } = string.Empty;
    public string BucketName { get; set; } = string.Empty;
}