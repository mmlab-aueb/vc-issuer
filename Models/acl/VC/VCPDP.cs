using Issuer.Data;
using Microsoft.Extensions.Configuration;
using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Linq;
using Microsoft.EntityFrameworkCore;


namespace vc_issuer.Models.acl.VC
{
    public class VCPDP:PDP
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        public VCPDP(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        public override string Issue(int endpointId, int clientId, ClientRequest clientRequest)
        {
            var authorizations = _context.authorization
                .Include(a => a.Client).Include(b => b.Operation).Include(c => c.Operation.Resource).Include(c => c.Operation.Resource.Endpoint)
                .Where(q => q.ClientID == clientId && q.Operation.Resource.EndpointID == endpointId).ToList();
            var endpoint = _context.endpoint.Where(q => q.ID == endpointId).FirstOrDefault();
            //TODO chech if null
            var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exp = DateTimeOffset.UtcNow.AddDays(15).ToUnixTimeSeconds();
            var iss = _configuration["iss_url"];
            //var payload = new JwtPayload(iss, null, new List<Claim>(), iat, exp);
            SHA256 hash = SHA256.Create();
            /*
                * The VC identifier (jti) is the hash of the wallet Id appended with the Id of the authorized
                * resources. Therefore, two VCs for the same wallet that include the same authorizations will
                * have the same jti
                */
            string jti = "";
            jti += clientId.ToString();
            var capabilities = new Dictionary<string, List<String>>();
            foreach (var resource in endpoint.Resources.OrderBy(q => q.ID))
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
                credential = new Models.acl.Credential()
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
                credential.isRevoked = false;
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
            if (clientRequest.authorization_details != "")
            {
                try
                {
                    JsonNode rar = JsonNode.Parse(clientRequest.authorization_details)!;
                    string type = rar["type"].ToString();
                    if (type == "pop-jwk")
                    {
                        var clientKey = rar["jwk"].Deserialize<Dictionary<String, String>>();
                        payload.Add("cnf", clientKey);
                    }
                    else if (type == "pop-did")
                    {
                        var clientKey = rar["did"].ToString();
                        payload.Add("sub", clientKey);
                    }

                }
                catch (Exception) { }
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
            return jwtTokenHandler.WriteToken(jwtToken);
        }
    }
}
