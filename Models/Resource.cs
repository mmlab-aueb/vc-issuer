﻿using Issuer.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Http;

namespace Issuer.Models
{
    public class Resource
    {

        public int ID { get; set; }
        public string Name { get; set; }
        public string OwnerId { get; set; }

        public ICollection<Endpoint> Endpoints { get; set; }
    }
}
