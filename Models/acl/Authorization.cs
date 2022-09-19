using Issuer.Data;
using Issuer.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace vc_issuer.Models.acl
{
    public class Authorization
    {
        [Key]
        public int ID { get; set; }

        public int ClientID { get; set; }
        public int OperationID { get; set; }
        public virtual Operation Operation { get; set; }
        public Client Client { get; set; }
    }
}
