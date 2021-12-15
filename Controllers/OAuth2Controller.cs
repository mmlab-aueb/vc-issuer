using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Issuer.Data;
using Issuer.Models;
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

        [Route("oauth2/authorize/{userId?}")]
        public IActionResult Authorize(String userId, String response_type, String client_id, String redirect_uri, String scope, String state)
        {
            if (userId == null || client_id == null || response_type == null || redirect_uri == null)
            {
                return Unauthorized();
            }

            if (!authorizeClient(userId, client_id))
            {
                return Unauthorized();
            }

            // Check if rederict_uri is allowed
            var redirectURI = _context.RedirectURI.Include(a => a.Client)
                .Where(q => q.OwnerId == userId && q.Client.ClientId == client_id && q.URI == redirect_uri).FirstOrDefault();
            if (redirectURI == null)
            {
                return Unauthorized();
            }

            if (response_type == "code")
            {
                // Check if there is still an active authorization code
                var client = _context.Client
                    .Where(q => q.ClientId == client_id && q.OwnerId == userId).FirstOrDefault();
                if (client == null)
                {
                    return Unauthorized();
                }
                string code  = createAuthorizationCode(userId, client.ID, redirect_uri);
                
                redirect_uri += "?code=" + code;
                if (state != null)
                    redirect_uri += "&state=" + state;
                return Redirect(redirect_uri);
            }

            return Unauthorized();

        }

        [Route("oauth2/token/{userId?}")]
        [HttpPost]
        public IActionResult token(String userId, String grant_type, String code, String client_id, String client_secret, String redirect_uri)
        {
            if (userId == null || grant_type == null)
            {
                return Unauthorized();
            }

            if (grant_type == "client_credentials")
            {
                (bool isauthorized, int clientId) = authorizeClient(userId);
                if (isauthorized)
                {
                    string jwt = createJWT(userId, clientId);
                    var response = new Dictionary<string, string>()
                    {
                        { "access_token", jwt},
                        { "token_type","bearer" },
                        { "expires_in","3600" },
                    };
                    return Ok(response);
                }
            }

            if (grant_type == "authorization_code")
            {
                if (code == null || client_id == null || client_secret == null || redirect_uri == null)
                {
                    return Unauthorized();
                }
                //Check if provided client_secret is correct
                (bool isauthenticated, int clientId) = authenticateClient(userId, client_id, client_secret);
                if (!isauthenticated)
                {
                    return Unauthorized();
                }
                //Check if provided code is correct
                bool isauthorized = authorizeClient(userId, clientId, code, redirect_uri);
                if (isauthorized)
                {
                    string jwt = createJWT(userId, clientId);
                    var response = new Dictionary<string, string>()
                    {
                        { "access_token", jwt},
                        { "token_type","bearer" },
                        { "expires_in","3600" },
                    };
                    return Ok(response);
                }
            }

            return Unauthorized();
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

        private (bool, int) authenticateClient(String userId, String client_id, String client_secret)
        {
            var client = _context.Client.Where(q => q.OwnerId == userId && q.ClientId == client_id && q.ClientSecret == client_secret).FirstOrDefault();
            if (client != null)
                return (true, client.ID);
            else
                return (false, 0);

        }

        /*
         * It checks is a client is authorized by a user.
         * It is used by the client authorization code grant.
         */
        private bool authorizeClient(String userId, String client_id)
        {
            var client = _context.Client.Where(q => q.OwnerId == userId && q.ClientId == client_id).FirstOrDefault();
            return client != null;
   
        }

        /*
         * It checks is a client is using a valid authetication code.
         * It is used by the client authorization code grant.
         */
        private bool authorizeClient(String userId, int clientId, string code, string redirect_uri)
        {
            var client = _context.OAuth2AuthorizationCode
                .Where(q => q.ClientID == clientId && q.OwnerId == userId && q.RedirectURI == redirect_uri && 
                q.CreationTime > DateTime.Now.AddMinutes(-2)).FirstOrDefault();
            return client != null;

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

        private String createAuthorizationCode(String userId, int clientId, String redirect_uri)
        {

            var  authCode = new OAuth2AuthorizationCode();
            authCode.ClientID = clientId;
            authCode.OwnerId = userId;
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[18];
            rng.GetBytes(randomBytes);
            string code = Base64UrlEncoder.Encode(randomBytes);
            authCode.Code = code;
            authCode.CreationTime = DateTime.Now;
            authCode.RedirectURI = redirect_uri;
            _context.Add(authCode);
            _context.SaveChanges();
            return code;
        }

        private String createJWT(String userId, int clientId)
        {
            var authorizations = _context.Authorization
                .Include(a => a.Client).Include(b => b.Operation).Include(c=>c.Operation.Resource)
                .Where(q => q.ClientID == clientId && q.OwnerId == userId).ToList();
            string privateKey = _configuration["jws_private_key_pem"];
            ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(privateKey);
            var signingCredentials = new SigningCredentials(
                key: new ECDsaSecurityKey(ecdsa),
                algorithm: SecurityAlgorithms.EcdsaSha256);

            var iat = DateTime.UtcNow;
            var exp = DateTime.UtcNow.AddDays(1);
            var iss = "https://as.controlthings.gr";
            var payload = new JwtPayload(iss, userId, new List<Claim>(), iat, exp);

            var capabilities = new Dictionary<string, List<String>>();
            foreach (var authorization in authorizations)
            {
                if (!capabilities.ContainsKey(authorization.Operation.Resource.Name))
                    capabilities.Add(authorization.Operation.Resource.Name, new List<string>());
                capabilities[authorization.Operation.Resource.Name].Add(authorization.Operation.OperationId);

            }
            payload.Add("capabilities", capabilities);
            var jwtToken = new JwtSecurityToken(new JwtHeader(signingCredentials), payload);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            return jwtTokenHandler.WriteToken(jwtToken);
            /*
            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = new List<Claim>();
            foreach (var authorization in authorizations)
            {
                claims.Add(new Claim("operations", authorization.Operation.URI));
            }
            

            var jwt = tokenHandler.CreateEncodedJwt(
                issuer: "https://as.controlthings.gr",
                audience: userId,
                subject: new ClaimsIdentity(claims.ToArray()),
                notBefore: null,
                expires: DateTime.UtcNow.AddDays(1),
                issuedAt: DateTime.UtcNow,
                signingCredentials: new SigningCredentials(
                    key: new ECDsaSecurityKey(ecdsa),
                    algorithm: SecurityAlgorithms.EcdsaSha256Signature)
                );

            return jwt;
            */
        }

        private String createVC(String userId, int clientId, Object clientKey= null)
        {
            var authorizations = _context.Authorization
                .Include(a => a.Client).Include(b => b.Operation).Include(c => c.Operation.Resource)
                .Where(q => q.ClientID == clientId && q.OwnerId == userId).ToList();
            string privateKey = _configuration["jws_private_key_pem"];
            ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(privateKey);
            var signingCredentials = new SigningCredentials(
                key: new ECDsaSecurityKey(ecdsa),
                algorithm: SecurityAlgorithms.EcdsaSha256);

            var iat = DateTime.UtcNow;
            var exp = DateTime.UtcNow.AddDays(1);
            var iss = _configuration["iss_url"];
            //var payload = new JwtPayload(iss, null, new List<Claim>(), iat, exp);
            var payload = new JwtPayload(iss, null, new List<Claim>(),null, null);
            var capabilities = new Dictionary<string, List<String>>();
            foreach (var authorization in authorizations)
            {
                if (!capabilities.ContainsKey(authorization.Operation.Resource.Name))
                    capabilities.Add(authorization.Operation.Resource.Name, new List<string>());
                capabilities[authorization.Operation.Resource.Name].Add(authorization.Operation.OperationId);

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
            var jwtToken = new JwtSecurityToken(new JwtHeader(signingCredentials), payload);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            return jwtTokenHandler.WriteToken(jwtToken);
        }
    }
}