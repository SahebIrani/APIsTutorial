using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Simple.Services
{
    public class TokenAuthenticationService : IAuthenticateService
    {
        private readonly IUserManagementService _userManagementService;
        private readonly TokenManagement _tokenManagement;

        public TokenAuthenticationService(IUserManagementService service, IOptions<TokenManagement> tokenManagement)
        {
            _userManagementService = service;
            _tokenManagement = tokenManagement.Value;
        }
        public bool IsAuthenticated(TokenRequest request, out string token)
        {
            token = string.Empty;

            if (!_userManagementService.IsValidUser(request.Username, request.Password)) return false;

            var claim = new[]
            {
                new Claim(ClaimTypes.Name, request.Username)
            };

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenManagement.Secret));
            var signingcredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var encryptKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenManagement.Encrypt));
            var encryptCredentials = new EncryptingCredentials(
                encryptKey,
                SecurityAlgorithms.Aes128KW,
                SecurityAlgorithms.Aes128CbcHmacSha256
            );

            var jwtToken = new JwtSecurityToken(
                _tokenManagement.Issuer,
                _tokenManagement.Audience,
                claim,
                expires: DateTime.Now.AddMinutes(_tokenManagement.AccessExpiration),
                signingCredentials: signingcredentials
            );

            var handler = new JwtSecurityTokenHandler();
            string tt = handler.WriteToken(jwtToken);

            token = tt;

            var rt = handler.ReadToken(tt);
            var rjt = handler.ReadJwtToken(tt);
            var claims = rjt.Claims.ToList();

            //◘◘◘◘

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = _tokenManagement.Issuer,
                Audience = _tokenManagement.Audience,
                Expires = DateTime.Now.AddMinutes(_tokenManagement.AccessExpiration),
                SigningCredentials = signingcredentials,
                EncryptingCredentials = encryptCredentials,
                Subject = new ClaimsIdentity(claim)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(descriptor);
            string encryptedJwt = tokenHandler.WriteToken(securityToken);

            token = encryptedJwt;

            var rt2 = tokenHandler.ReadToken(encryptedJwt);
            var rjt2 = tokenHandler.ReadJwtToken(encryptedJwt);
            var claims2 = rjt2.Claims.ToList();

            byte[] secret = Encoding.ASCII.GetBytes(_tokenManagement.Secret);
            byte[] decryptionKey = Encoding.ASCII.GetBytes(_tokenManagement.Encrypt);
            var tvp = new TokenValidationParameters
            {
                ValidAudience = _tokenManagement.Audience,
                ValidIssuer = _tokenManagement.Issuer,
                //TokenDecryptionKey = new X509SecurityKey(new X509Certificate2("./idsrv3test.pfx", "idsrv3test")),
                TokenDecryptionKey = new SymmetricSecurityKey(decryptionKey),
                IssuerSigningKey = new SymmetricSecurityKey(secret),
                RequireSignedTokens = false
            };
            var clp = tokenHandler.ValidateToken(encryptedJwt, tvp, out securityToken);
            var cllist = clp.Claims.ToList();

            var tokenHandler2 = new JwtSecurityTokenHandler { TokenLifetimeInMinutes = 5 };
            var securityToken2 = tokenHandler2.CreateJwtSecurityToken(
                issuer: "client_using_jwt",
                audience: "http://localhost:5000/connect/token",
                issuedAt: DateTime.Now,
                expires: DateTime.Now.AddMinutes(_tokenManagement.AccessExpiration),
                notBefore: DateTime.Now.AddMinutes(0),
                subject: new ClaimsIdentity(new List<Claim> { new Claim("sub", "client_using_jwt") }),
                signingCredentials: new SigningCredentials(new X509SecurityKey(new X509Certificate2("./idsrv3test.pfx", "idsrv3test")), "RS256"),
                encryptingCredentials: new X509EncryptingCredentials(new X509Certificate2("./idsrv3test.pfx", "idsrv3test"))
            );
            var tw = tokenHandler2.WriteToken(securityToken2);

            return true;
        }
    }
}
