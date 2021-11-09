using Issuer.Data;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Issuer.Models
{
    public class Authorization
    {

        public int ID { get; set; }
        public string OwnerId { get; set; }
        public int ClientID { get; set; }
        public int EndpointID { get; set; }
        public virtual Endpoint Endpoint { get; set; }
        public Client Client { get; set; }


    }
}
