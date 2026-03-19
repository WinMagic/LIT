/*
* Copyright (C) 2026 WinMagic Inc.
*
* This file is part of the WinMagic LIT reference project.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of the WinMagic Inc.
* Commercial License, which can be found at https://winmagic.com/en/legal/commercial_license/
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

using LIT.ServerMVC.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace LIT.ServerMVC.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Device> Devices { get; set; }
        public DbSet<KeyRegistration> KeyRegistrations { get; set; }
        public DbSet<ServerCert> ServerCerts { get; set; }
        public DbSet<TodoItem> TodoItems { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserId);
                entity.HasIndex(e => e.UserName).IsUnique();
                //sql server database
                //entity.Property(e => e.DateCreated).HasDefaultValueSql("GETUTCDATE()");

                //sqlite database
                entity.Property(e => e.DateCreated).HasDefaultValueSql("DATETIME('now')");
            });

            modelBuilder.Entity<Device>(entity =>
            {
                entity.HasKey(e => e.DeviceId);

                //sql server database
                //entity.Property(e => e.DateCreated).HasDefaultValueSql("GETUTCDATE()");

                //sqlite database
                entity.Property(e => e.DateCreated).HasDefaultValueSql("DATETIME('now')");
            });

            modelBuilder.Entity<KeyRegistration>(entity =>
            {
                entity.HasKey(e => e.KeyRegistrationId);

                //sql server database
                //entity.Property(e => e.DateCreated).HasDefaultValueSql("GETUTCDATE()");
                //entity.Property(e => e.DateModified).HasDefaultValueSql("GETUTCDATE()");

                //sqlite database
                entity.Property(e => e.DateCreated).HasDefaultValueSql("DATETIME('now')");
                entity.Property(e => e.DateModified).HasDefaultValueSql("DATETIME('now')");

                entity.HasOne(e => e.User)
                .WithMany(u => u.Keys)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();

                entity.HasOne(e => e.Device)
                .WithMany(d => d.Keys)
                .HasForeignKey(e => e.DeviceId)
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();
            });

            modelBuilder.Entity<ServerCert>(entity =>
            {
                entity.HasKey(e => e.Index);

                //sql server database
                //entity.Property(e => e.DateCreated).HasDefaultValueSql("GETUTCDATE()");

                //sqlite database
                entity.Property(e => e.DateCreated).HasDefaultValueSql("DATETIME('now')");
            });

            modelBuilder.Entity<TodoItem>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.HasOne(e => e.User)
                .WithMany(t => t.TodoItems)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();

                //sqlite database
                entity.Property(e => e.DateCreated).HasDefaultValueSql("DATETIME('now')");
            });
        }
    }
}
