using Issuer.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Http;

namespace vc_issuer.Models.acl
{
    public class Resource
    {

        [Key]
        public int ID { get; set; }
        public string Name { get; set; }
        public string URI { get; set; }

        public int EndpointID { get; set; }
        public Endpoint Endpoint { get; set; }
        public ICollection<Operation> Operations { get; set; }
    }
}
