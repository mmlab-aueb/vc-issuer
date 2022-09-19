using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Issuer.Models;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Diagnostics;
using System.Linq;
using vc_issuer.Models.acl;

namespace Issuer.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        public DbSet<Client> client { get; set; }
        public DbSet<vc_issuer.Models.acl.Endpoint> endpoint { get; set; }
        public DbSet<Operation> operation { get; set; }
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
