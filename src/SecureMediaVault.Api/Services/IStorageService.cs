namespace SecureMediaVault.Api.Services;

public interface IStorageService
{
    Task UploadFileAsync(string key, Stream fileStream);

    Task<Stream> GetFileAsync(string key);
}