using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Issuer.Models;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Diagnostics;
using System.Linq;

namespace Issuer.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        public DbSet<Client> client { get; set; }
        public DbSet<Models.Endpoint> endpoint { get; set; }
        public DbSet<Models.Operation> operation { get; set; }
        public DbSet<Resource> resource { get; set; }        
        public DbSet<Authorization> authorization { get; set; }
        public DbSet<Credential> credential { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Credential>()
                .HasAlternateKey(c => c.revocationIndex);
        }
    }
}
