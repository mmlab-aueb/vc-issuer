using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Issuer.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
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
        public IActionResult Issue(String grant_type)
        {
            if (grant_type == null)
            {
                return Unauthorized();
            }

            if (grant_type == "client_credentials")
            {
                (bool isauthorized, int clientId) = AuthorizeClient();
                (bool isauthenticated, object clientKey) = HandleDPoP();
                if (isauthorized && isauthenticated)
                {
                    HandleDPoP();
                    List<String> vc = CreateVCs(clientId, clientKey);
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
         * It checks is a client is authorized based on the Authorize HTTP header.
         * It is used by the client credential grant.
         * It returns the client Id
         */
        private (bool, int) AuthorizeClient()
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
        private (bool, Object) HandleDPoP()
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

        private List<String> CreateVCs( int clientId, Object clientKey= null)
        {
            var result = new List<String>();
            var authorizations = _context.authorization
                .Include(a => a.Client).Include(b => b.Operation).Include(c => c.Operation.Resource).Include(c => c.Operation.Resource.Endpoint)
                .Where(q => q.ClientID == clientId).ToList();
            var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exp = DateTimeOffset.UtcNow.AddDays(15).ToUnixTimeSeconds();
            var iss = _configuration["iss_url"];
            //var payload = new JwtPayload(iss, null, new List<Claim>(), iat, exp);
            SHA256 hash = SHA256.Create();

            foreach (var endpoint in authorizations.Select(q=>q.Operation.Resource.Endpoint).Distinct())
            {
                /*
                 * The VC identifier (jti) is the hash of the wallet Id appended with the Id of the authorized
                 * resources. Therefore, two VCs for the same wallet that include the same authorizations will
                 * have the same jti
                 */ 
                string jti = "";
                jti += clientId.ToString();
                var capabilities = new Dictionary<string, List<String>>();
                foreach (var resource in endpoint.Resources.OrderBy(q=>q.ID))
                {
                    capabilities.Add(resource.URI, new List<string>());
                    foreach (var operation in resource.Operations.OrderBy(q => q.ID))
                    {
                        capabilities[resource.URI].Add(operation.URI);
                        jti += operation.ID.ToString();
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
                
                //Strore the credential in the DB
                jti = WebEncoders.Base64UrlEncode(hash.ComputeHash(Encoding.UTF8.GetBytes(jti)));
                var credential = _context.credential.Where(q => q.jti == jti).FirstOrDefault();
                if (credential == null)
                {
                    credential = new Models.Credential()
                    {
                        jti = jti,
                        aud = endpoint.URI,
                        iat = iat,
                        exp = exp,
                        type = "CapabilitiesCredential",
                        isRevoked = false,
                        payload = JsonSerializer.Serialize(vc)
                    };
                    _context.Add(credential);
                    _context.SaveChanges();
                }
                else
                {
                    credential.iat = iat;
                    credential.exp = exp;
                    isRevoked = false;
                    _context.Update(credential);
                    _context.SaveChanges();

                }
                //Revocation information
                vc["credentialStatus"] = new Dictionary<String, Object>() {
                    {"type", "RevocationList2021Status" },
                    { "statusListIndex", credential.revocationIndex % 2000},
                    {"statusListCredential", "https://issuer.mmlab.edu.gr/credential/status" }
                };
                var payload = new JwtPayload(iss, null, new List<Claim>(), null, null);
                if (clientKey != null)
                {
                    payload.Add("cnf", clientKey);
                }
                payload.Add("jti", jti);
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
        }
        
    }
}