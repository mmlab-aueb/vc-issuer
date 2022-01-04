using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Issuer.Data;

namespace Issuer.Models
{
    public class Operation
    {

        public int ID { get; set; }
        public string Name { get; set; }
        public string OperationId { get; set; }
        public string OwnerId { get; set; }

        public Resource Resource { get; set; }
        public ICollection<Authorization> Authorizations { get; set; }
    }
}