using System;
using System.Collections.Generic;
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
            var redirectURI = _context.RedirectURI.Include(a => a.Client).IgnoreQueryFilters()
                .Where(q => q.OwnerId == userId && q.Client.ClientId == client_id && q.URI == redirect_uri).FirstOrDefault();
            if (redirectURI == null)
            {
                return Unauthorized();
            }

            if (response_type == "code")
            {
                // Check if there is still an active authorization code
                var client = _context.Client.IgnoreQueryFilters()
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

        private (bool, int) authenticateClient(String userId, String client_id, String client_secret)
        {
            var client = _context.Client.IgnoreQueryFilters().Where(q => q.OwnerId == userId && q.ClientId == client_id && q.ClientSecret == client_secret).FirstOrDefault();
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
            var client = _context.Client.IgnoreQueryFilters().Where(q => q.OwnerId == userId && q.ClientId == client_id).FirstOrDefault();
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

                var client = _context.Client.IgnoreQueryFilters().Where(q => q.OwnerId == userId && q.ClientId == credentials[0] && q.ClientSecret == credentials[1]).FirstOrDefault();
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
            var authorizations = _context.Authorization.IgnoreQueryFilters()
                .Include(a => a.Client).Include(b => b.Endpoint).Include(c=>c.Endpoint.Resource)
                .Where(q => q.ClientID == clientId && q.OwnerId == userId).ToList();
            string privateKey = _configuration["jws_private_key_pem"];
            ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(privateKey);
            var signingCredentials = new SigningCredentials(
                key: new ECDsaSecurityKey(ecdsa),
                algorithm: SecurityAlgorithms.EcdsaSha256);

            var iat = DateTime.UtcNow;
            var exp = DateTime.UtcNow.AddDays(1);
            var payload = new JwtPayload(null, "", new List<Claim>(), iat, exp);
            var capabilities = new Dictionary<string, List<String>>();
            foreach (var authorization in authorizations)
            {
                if (!capabilities.ContainsKey(authorization.Endpoint.Resource.Name))
                    capabilities.Add(authorization.Endpoint.Resource.Name, new List<string>());
                capabilities[authorization.Endpoint.Resource.Name].Add(authorization.Endpoint.URI);

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
                claims.Add(new Claim("operations", authorization.Endpoint.URI));
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
    }
}