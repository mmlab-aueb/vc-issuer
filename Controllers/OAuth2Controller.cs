using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Issuer.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Issuer.Controllers
{
    [Microsoft.AspNetCore.Authorization.AllowAnonymous]
    public class OAuth2Controller : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public OAuth2Controller(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        


        [Route("oauth2/issue/{userId?}")]
        [HttpPost]
        public IActionResult issue(String userId, String grant_type)
        {
            if (userId == null || grant_type == null)
            {
                return Unauthorized();
            }

            if (grant_type == "client_credentials")
            {
                (bool isauthorized, int clientId) = authorizeClient(userId);
                (bool isauthenticated, object clientKey) = handleDPoP();
                if (isauthorized && isauthenticated)
                {
                    handleDPoP();
                    string vc = createVC(userId, clientId, clientKey);
                    var response = new Dictionary<string, string>()
                    {
                        { "vc", vc},
                    };
                    return Ok(response);
                }
            }

            return Unauthorized();
        }


        /*
         * It checks is a client is authorized based on the Authorize HTTP header.
         * It is used by the client credential grant.
         * It returns the client Id
         */
        private (bool, int) authorizeClient(String userId)
        {
            try
            {
                var header = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                string[] credentials = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter)).Split(":");

                var client = _context.Client.Where(q => q.OwnerId == userId && q.ClientId == credentials[0] && q.ClientSecret == credentials[1]).FirstOrDefault();
                if (client != null)
                    return (true, client.ID);
                else
                    return (false, 0);
            }
            catch(Exception)
            {
                return (false, 0);
            }
        }

        /*
         * It checks if DPoP header is present.
         * If there is no DPoP header it returns true
         * If there is a valid DPoP header it returns true and the client key
         * If ther is an invlaid DPoP header it returns false
         */
        private (bool, Object) handleDPoP()
        {
            try
            {
                var dpop_header = Request.Headers["DPoP"];
                if (dpop_header.IsNullOrEmpty()) return (true, null);
                var tokenHandler = new JwtSecurityTokenHandler();
                var dpop = tokenHandler.ReadJwtToken(dpop_header);
                string clietKeyJSON = dpop.Header.First(q => q.Key == "jwk").Value.ToString();
                var clietJWK = new JsonWebKey(clietKeyJSON);
                var validationParameters = new TokenValidationParameters()
                {
                    IssuerSigningKey = clietJWK,
                    ValidateLifetime = false, 
                    ValidateAudience = false,
                    ValidateIssuer = false
                };

                tokenHandler.ValidateToken(dpop_header, validationParameters, out _);
                return (true, dpop.Header.First(q => q.Key == "jwk").Value);
            }
            catch (Exception)
            {
                return (false, null);
            }

        }



        private String createVC(String userId, int clientId, Object clientKey= null)
        {
            var authorizations = _context.Authorization
                .Include(a => a.Client).Include(b => b.Operation).Include(c => c.Operation.Resource)
                .Where(q => q.ClientID == clientId && q.OwnerId == userId).ToList();
            var iat = DateTime.UtcNow;
            var exp = DateTime.UtcNow.AddDays(1);
            var iss = _configuration["iss_url"];
            //var payload = new JwtPayload(iss, null, new List<Claim>(), iat, exp);
            var payload = new JwtPayload(iss, null, new List<Claim>(),null, null);
            var capabilities = new Dictionary<string, List<String>>();
            foreach (var authorization in authorizations)
            {
                if (!capabilities.ContainsKey(authorization.Operation.Resource.ResourceId))
                    capabilities.Add(authorization.Operation.Resource.ResourceId, new List<string>());
                capabilities[authorization.Operation.Resource.ResourceId].Add(authorization.Operation.OperationId);

            }
            if (capabilities.Count() == 1){
                payload.Add("aud", capabilities.First().Key);
            } 
            var vc = new Dictionary<String, Object>()
            {
                {"@context", new String[]{ "https://www.w3.org/2018/credentials/v1", "https://mm.aueb.gr/contexts/capabilities/v1"}},
                {"type", new String[]{ "VerifiableCredential", "CapabilitiesCredential"} },
                {
                    "credentialSubject", new Dictionary<String, Object>()
                    {
                        {"capabilities",capabilities}
                    } 
                }

            };
            if (clientKey != null)
            {
                payload.Add("cnf", clientKey);
            }
            payload.Add("vc", vc);
            var signingJWK = new JsonWebKey(_configuration["jwk"]);
            var publicJWK = new JsonWebKey(_configuration["jwk"]);
            publicJWK.D = null;
            var jwtHeader = new JwtHeader(
                new SigningCredentials(
                    key: signingJWK,
                    algorithm: SecurityAlgorithms.EcdsaSha256)
                );
            jwtHeader.Add("jwk", publicJWK);
            var jwtToken = new JwtSecurityToken(jwtHeader, payload);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            return jwtTokenHandler.WriteToken(jwtToken);
        }
    }
}