namespace SecureMediaVault.Api.Services;

public interface ICryptoService
{
    byte[] GenerateDek();

    byte[] EncryptDek(byte[] dek);

    byte[] DecryptDek(byte[] encryptedDek);

    Task EncryptStreamAsync(Stream inputStream, Stream outputStream, byte[] dek);

    Task DecryptStreamAsync(Stream inputStream, Stream outputStream, byte[] dek);
}