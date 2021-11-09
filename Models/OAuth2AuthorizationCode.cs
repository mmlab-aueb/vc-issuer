using Issuer.Data;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Issuer.Models
{
    public class OAuth2AuthorizationCode
    {

        public int ID { get; set; }

        public string Code { get; set; }

        public DateTime CreationTime { get; set; }

        public string OwnerId { get; set; }

        public int ClientID { get; set; }

        public string RedirectURI { get; set; }

    }
}
