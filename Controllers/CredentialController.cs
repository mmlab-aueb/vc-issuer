using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Issuer.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Issuer.Controllers
{
    public class CredentialController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public CredentialController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [Route("credential/status")]
        public IActionResult Status()
        {
            return Ok();
        }

        /*
         * Used for testing verifier implementations
         */
        [Route("credential/teststatus")]
        public IActionResult TestStatus()
        {
            /*
             * Still in progress
             * It generates a revocation list with the
             * 9th VC revoked
             */

            byte[] bytes = new byte[2000]; //It holds 16K VCs. This the the mimimum size according to https://w3c-ccg.github.io/vc-status-list-2021/#revocationlist2021status
            int bitindex = 9; //VC with index 9 is revoked. Note the first index is 0
            int index = bitindex / 8;
            int bit = bitindex % 8;
            byte mask = (byte)(1 << bit);
            bytes[1] |= mask;
            var s = Convert.ToBase64String(bytes);
            /*
             * Created and sign the revocation list
             */
            var response = createRevocationList(s);
            return Ok(response);
        }

        private String createRevocationList(String bitstring64)
        {

            var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exp = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds();
            var iss = _configuration["iss_url"];
            var payload = new JwtPayload(iss, null, new List<Claim>(), null, null);
            payload.Add("iat", iat);
            var signingJWK = new JsonWebKey(_configuration["jwk"]);
            var publicJWK = new JsonWebKey(_configuration["jwk"]);
            publicJWK.D = null;
            var jwtHeader = new JwtHeader(
                new SigningCredentials(
                    key: signingJWK,
                    algorithm: SecurityAlgorithms.EcdsaSha256)
                );
            jwtHeader.Add("jwk", publicJWK);
            var vc = new Dictionary<String, Object>()
            {
                {"@context", new String[]{ "https://www.w3.org/2018/credentials/v1", "https://w3id.org/vc/status-list/v1"}},
                {"type", new String[]{ "VerifiableCredential", "StatusList2021Credential" } },
                {
                    "credentialSubject", new Dictionary<String, Object>()
                    {
                        {"type","RevocationList2021" },
                        {"encodedList",bitstring64} //FIX that, it must be GZIPed
                    }
                }

            };
            payload.Add("vc", vc);
            var jwtToken = new JwtSecurityToken(jwtHeader, payload);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            return jwtTokenHandler.WriteToken(jwtToken);

        }
    }
}
