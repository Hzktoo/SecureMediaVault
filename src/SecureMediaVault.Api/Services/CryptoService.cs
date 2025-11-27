using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace SecureMediaVault.Api.Services;

public class CryptoService : ICryptoService
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int BufferSize = 81920;

    private readonly byte[] _kek; 

    public CryptoService(IConfiguration config)
    {
        var kekPath = config["Encryption:MasterKeyPath"];

        if (string.IsNullOrEmpty(kekPath) || !File.Exists(kekPath))
        {
            var kekHex = config["Encryption:MasterKey"];
            if (string.IsNullOrEmpty(kekHex))
                throw new Exception("Master Key (KEK) not found in secrets or config.");

            _kek = Convert.FromHexString(kekHex);
        }
        else
        {
            var kekHex = File.ReadAllText(kekPath).Trim();
            _kek = Convert.FromHexString(kekHex);
        }

        if (_kek.Length != KeySize)
            throw new Exception($"KEK must be {KeySize} bytes.");
    }

    public byte[] GenerateDek()
    {
        return RandomNumberGenerator.GetBytes(KeySize);
    }


    public byte[] EncryptDek(byte[] dek)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipherText = new byte[dek.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_kek, TagSize);
        aes.Encrypt(nonce, dek, cipherText, tag);

        var result = new byte[NonceSize + cipherText.Length + TagSize];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(cipherText, 0, result, NonceSize, cipherText.Length);
        Buffer.BlockCopy(tag, 0, result, NonceSize + cipherText.Length, TagSize);

        return result;
    }

    public byte[] DecryptDek(byte[] encryptedDek)
    {
        var nonce = encryptedDek.AsSpan(0, NonceSize);
        var tag = encryptedDek.AsSpan(encryptedDek.Length - TagSize, TagSize);
        var cipherText = encryptedDek.AsSpan(NonceSize, encryptedDek.Length - NonceSize - TagSize);

        var dek = new byte[cipherText.Length];

        using var aes = new AesGcm(_kek, TagSize);
        aes.Decrypt(nonce, cipherText, tag, dek);

        return dek;
    }

    public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, byte[] dek)
    {
        using var aes = Aes.Create();
        aes.Key = dek;
        aes.GenerateIV(); 

        await outputStream.WriteAsync(aes.IV, 0, aes.IV.Length);

        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);

        await inputStream.CopyToAsync(cryptoStream);
    }

    public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream, byte[] dek)
    {
        using var aes = Aes.Create();
        aes.Key = dek;

        var iv = new byte[aes.BlockSize / 8];
        var bytesRead = await inputStream.ReadAsync(iv, 0, iv.Length);
        if (bytesRead < iv.Length) throw new Exception("Invalid file format (missing IV)");

        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read);

        await cryptoStream.CopyToAsync(outputStream);
    }
}