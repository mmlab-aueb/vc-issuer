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
        public DbSet<Models.Operation> Operation { get; set; }
        public DbSet<Resource> Resource { get; set; }
        public DbSet<Client>   Client { get; set; }
        public DbSet<Authorization> Authorization { get; set; }
    }
}
