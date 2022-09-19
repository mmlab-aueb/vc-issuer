using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace vc_issuer.Models.acl
{
    public class Credential
    {
        [Key]
        public string jti { get; set; }
        public long exp { get; set; }
        public long iat { get; set; }
        public string aud { get; set; }
        public string type { get; set; }
        public string payload { get; set; }

        [DefaultValue(false)]
        public bool isRevoked { get; set; }

        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int revocationIndex { get; set; }
    }
}
