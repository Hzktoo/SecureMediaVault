using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureMediaVault.Api.Data.Entities;

namespace SecureMediaVault.Api.Data;


public class AppDbContext : IdentityDbContext<AppUser, IdentityRole<Guid>, Guid>
{
    public DbSet<MediaObject> MediaObjects { get; set; }

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder); 

        builder.Entity<AppUser>()
            .HasMany<MediaObject>() 
            .WithOne(m => m.AppUser)  
            .HasForeignKey(m => m.AppUserId) 
            .OnDelete(DeleteBehavior.Cascade); 
    }
}