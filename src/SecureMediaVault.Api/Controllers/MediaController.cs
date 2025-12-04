using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureMediaVault.Api.Data;
using SecureMediaVault.Api.Data.Entities;
using SecureMediaVault.Api.Services;
using Serilog;

namespace SecureMediaVault.Api.Controllers;

[ApiController]
[Route("api/media")]
[Authorize] 
public class MediaController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly UserManager<AppUser> _userManager;
    private readonly IStorageService _storage;
    private readonly ICryptoService _crypto;

    public MediaController(
        AppDbContext db,
        UserManager<AppUser> userManager,
        IStorageService storage,
        ICryptoService crypto)
    {
        _db = db;
        _userManager = userManager;
        _storage = storage;
        _crypto = crypto;
    }

    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("No file uploaded");

        var userIdString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userIdString == null) return Unauthorized();

        var userId = Guid.Parse(userIdString);

        var dek = _crypto.GenerateDek();

        var encryptedDek = _crypto.EncryptDek(dek);

        var mediaId = Guid.NewGuid();
        var storageKey = $"{userId}/{mediaId}";

        var mediaObject = new MediaObject
        {
            Id = mediaId,
            AppUserId = userId,
            FileName = file.FileName,
            ContentType = file.ContentType,
            FileSize = file.Length,
            StorageKey = storageKey,
            EncryptedDek = encryptedDek,
            CreatedAt = DateTime.UtcNow
        };

        var tempFilePath = Path.GetTempFileName();

        try
        {
            using (var fileStream = System.IO.File.Create(tempFilePath))
            {
                await using (var inputStream = file.OpenReadStream())
                {
                    await _crypto.EncryptStreamAsync(inputStream, fileStream, dek);
                }
            }

            using (var uploadStream = System.IO.File.OpenRead(tempFilePath))
            {
                await _storage.UploadFileAsync(storageKey, uploadStream);
            }
        }
        finally
        {
            if (System.IO.File.Exists(tempFilePath))
            {
                System.IO.File.Delete(tempFilePath);
            }
        }

        _db.MediaObjects.Add(mediaObject);
        await _db.SaveChangesAsync();

        return Ok(new { id = mediaId, fileName = file.FileName });
    }

    [HttpGet("{id}/download")]
    public async Task<IActionResult> Download(Guid id)
    {
        var userIdString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userId = Guid.Parse(userIdString!);

        var mediaObject = await _db.MediaObjects.FindAsync(id);

        if (mediaObject == null) return NotFound("File not found in database");

        if (mediaObject.AppUserId != userId) return Forbid();

        var dek = _crypto.DecryptDek(mediaObject.EncryptedDek);

        var encryptedStream = await _storage.GetFileAsync(mediaObject.StorageKey);

        Response.Headers.Append("Content-Disposition", $"attachment; filename=\"{mediaObject.FileName}\"");
        Response.ContentType = mediaObject.ContentType;

        try
        {
            await _crypto.DecryptStreamAsync(encryptedStream, Response.Body, dek);
        }
        catch (Exception ex)
        {
            return BadRequest($"Decryption error: {ex.Message}");
        }

        return new EmptyResult();
    }

    [HttpGet("list")]
    public IActionResult GetMyFiles()
    {
        var userIdString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userId = Guid.Parse(userIdString!);

        var files = _db.MediaObjects
            .Where(f => f.AppUserId == userId)
            .Select(f => new
            {
                f.Id,
                f.FileName,
                f.ContentType,
                f.FileSize,
                f.CreatedAt
            })
            .ToList();

        return Ok(files);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var userIdString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userId = Guid.Parse(userIdString!);

        var mediaObject = await _db.MediaObjects.FindAsync(id);

        if (mediaObject == null) return NotFound();

        if (mediaObject.AppUserId != userId) return Forbid();

        await _storage.DeleteFileAsync(mediaObject.StorageKey);

        _db.MediaObjects.Remove(mediaObject);
        await _db.SaveChangesAsync();

        Log.Information("User {UserId} deleted file {FileName}", userId, mediaObject.FileName);

        return NoContent();
    }
}
