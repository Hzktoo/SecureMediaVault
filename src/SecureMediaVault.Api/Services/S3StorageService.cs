using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using SecureMediaVault.Api.Options;

namespace SecureMediaVault.Api.Services;

public class S3StorageService : IStorageService
{
    private readonly IAmazonS3 _s3Client;
    private readonly MinioSettings _minioSettings;

    public S3StorageService(IOptions<MinioSettings> minioSettings)
    {
        _minioSettings = minioSettings.Value;

        var config = new AmazonS3Config
        {
            ServiceURL = $"http://{_minioSettings.Endpoint}", 
            ForcePathStyle = true, 
            AuthenticationRegion = "us-east-1" 
        };

        // 2. Створюємо сам S3-клієнт
        _s3Client = new AmazonS3Client(
            _minioSettings.AccessKey,
            _minioSettings.SecretKey,
            config
        );
    }


    public async Task UploadFileAsync(string key, Stream fileStream)
    {
        var request = new PutObjectRequest
        {
            BucketName = _minioSettings.BucketName,
            Key = key, 
            InputStream = fileStream
        };

        await _s3Client.PutObjectAsync(request);
    }

    public async Task<Stream> GetFileAsync(string key)
    {
        var request = new GetObjectRequest
        {
            BucketName = _minioSettings.BucketName,
            Key = key
        };

        var response = await _s3Client.GetObjectAsync(request);
        return response.ResponseStream;
    }
}