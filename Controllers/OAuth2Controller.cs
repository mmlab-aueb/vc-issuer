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

        


        [Route("oauth2/issue")]
        [HttpPost]
        public IActionResult issue(String grant_type)
        {
            if (grant_type == null)
            {
                return Unauthorized();
            }

            if (grant_type == "client_credentials")
            {
                (bool isauthorized, int clientId) = authorizeClient();
                (bool isauthenticated, object clientKey) = handleDPoP();
                if (isauthorized && isauthenticated)
                {
                    handleDPoP();
                    List<String> vc = createVCs(clientId, clientKey);
                    var response = new Dictionary<string, List<string>>()
                    {
                        { "vc", vc},
                    };
                    return Ok(response);
                }
            }

            return Unauthorized();
        }

        /*
         * Returns the revocation list
         */ 
        [Route("oauth2/status")]
        [HttpGet]
        public IActionResult status()
        {
            /*
             * Still in progress
             * It generates a revocation list with the
             * 9th VC revoked
             */
            
            byte[] bytes = new byte[500]; //It holds 4K VCs
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


        /*
         * It checks is a client is authorized based on the Authorize HTTP header.
         * It is used by the client credential grant.
         * It returns the client Id
         */
        private (bool, int) authorizeClient()
        {
            try
            {
                var header = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                string[] credentials = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter)).Split(":");

                var client = _context.client.Where(q => q.ClientId == credentials[0] && q.ClientSecret == credentials[1]).FirstOrDefault();
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



        private List<String> createVCs( int clientId, Object clientKey= null)
        {
            var result = new List<String>();
            var authorizations = _context.authorization
                .Include(a => a.Client).Include(b => b.Operation).Include(c => c.Operation.Resource).Include(c => c.Operation.Resource.Endpoint)
                .Where(q => q.ClientID == clientId).ToList();
            var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exp = DateTimeOffset.UtcNow.AddDays(15).ToUnixTimeSeconds();
            var iss = _configuration["iss_url"];
            //var payload = new JwtPayload(iss, null, new List<Claim>(), iat, exp);
            
            foreach (var endpoint in authorizations.Select(q=>q.Operation.Resource.Endpoint).Distinct())
            {
                var payload = new JwtPayload(iss, null, new List<Claim>(), null, null);
                var capabilities = new Dictionary<string, List<String>>();
                foreach (var resource in endpoint.Resources)
                {
                    capabilities.Add(resource.URI, new List<string>());
                    foreach (var operation in resource.Operations)
                    {
                        capabilities[resource.URI].Add(operation.URI);
                    }
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
                payload.Add("aud", endpoint.URI);
                payload.Add("iat", iat);
                payload.Add("exp", exp);
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
                result.Add(jwtTokenHandler.WriteToken(jwtToken));
            }
            return result;
            /*
            foreach (var authorization in authorizations)
            {
                if (!capabilities.ContainsKey(authorization.Operation.Resource.URI))
                    capabilities.Add(authorization.Operation.Resource.URI, new List<string>());
                capabilities[authorization.Operation.Resource.URI].Add(authorization.Operation.URI);

            }
            if (authorizations.Count() > 0){
                payload.Add("aud", authorizations.First().Operation.Resource.Endpoint.URI);
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
            */
        }

        private String createRevocationList(String bitstring64)
        {
       

            var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exp = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds();
            var iss = _configuration["iss_url"];
            var payload = new JwtPayload(iss, null, new List<Claim>(), null, null);
            payload.Add("RevocationList", bitstring64);
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
            var jwtToken = new JwtSecurityToken(jwtHeader, payload);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            return jwtTokenHandler.WriteToken(jwtToken);
           
        }
    }
}