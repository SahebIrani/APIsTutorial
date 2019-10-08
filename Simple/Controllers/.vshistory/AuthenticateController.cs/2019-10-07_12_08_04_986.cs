using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

using Sample.Models;

using Simple.Models;

namespace Simple.Controllers
{
    public class AuthenticateController : Controller
    {
        private readonly UserManager<ApplicationUser> UserManager;
        public AuthenticateController(UserManager<ApplicationUser> userManager) => UserManager = userManager;


        [HttpGet("UsersAndClaims"), Authorize]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        //[Authorize
        //    (
        //        AuthenticationSchemes =
        //            "Identity.Application" + "," +
        //                JwtBearerDefaults.AuthenticationScheme
        //    )
        //]
        public async Task<IActionResult> GettAsync(CancellationToken ct)
        {
            //IEnumerable<Claim> claims = User.Claims;
            //Claim userId = User.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub);
            //var tk = new JwtSecurityTokenHandler();
            //var deress = tk.ValidateToken(
            //    authToken,
            //    new TokenValidationParameters
            //    {
            //        ValidAudience = "MyAudience",
            //        ValidIssuer = "MyIssuer",
            //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),
            //        RequireSignedTokens = false,
            //    }
            //    , out SecurityToken securityTokenee
            //);

            string? authToken = HttpContext.Request.Headers[HeaderNames.Authorization].ToString().Substring("Bearer".Length).TrimStart();
            var getClaims = GetClaimsPrincipal(authToken);
            var cl = getClaims.Claims.ToList();

            var jwt2 = new JwtSecurityTokenHandler().ReadToken(authToken);
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(authToken);
            var principal = jwt.Claims.ToList();

            var p1 = principal.Select(a => new { a.Type, a.Value }).First(c => c.Type == ClaimTypes.NameIdentifier);
            var p11 = principal.Select(a => new { a.Type, a.Value }).First(c => c.Type == ClaimTypes.Name);
            var p111 = principal.Select(a => new { a.Type, a.Value }).First(c => c.Type == ClaimTypes.Actor);
            var p1111 = principal.Select(a => new { a.Type, a.Value }).First(c => c.Type == ClaimTypes.Role);
            var p11111 = principal.Select(a => new { a.Type, a.Value }).First(c => c.Type == ClaimTypes.MobilePhone);
            var p111111 = principal.Select(a => new { a.Type, a.Value }).First(c => c.Type == ClaimTypes.Country);
            var p1111111 = principal.Select(a => new { a.Type, a.Value }).First(c => c.Type == ClaimTypes.Webpage);

            var users = await UserManager.Users.ToListAsync(ct);
            var claims = new[] { p1, p11, p111, p1111, p11111, p111111, p1111111 };

            return Ok(new { users, claims });
        }

        [HttpPost("GetToken")]
        public async Task<IActionResult> LoginAsync([FromBody] LoginnModel model)
        {
            ApplicationUser user = await UserManager.FindByNameAsync(model.Username);
            if (user != null && await UserManager.CheckPasswordAsync(user, model.Password))
            {
                var authClaims = new[]
                {
                    //new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    //new Claim(JwtRegisteredClaimNames.Jti, user.Id),
                    ////new Claim(ClaimTypes.NameIdentifier, user.Id),
                    ////new Claim(ClaimTypes.GivenName, user.UserName),
                    //new Claim(ClaimTypes.Email, user.Email),

                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Actor, "SinjulMSBH"),
                    new Claim(ClaimTypes.Role,"Admin"),
                    new Claim(ClaimTypes.MobilePhone,"09215899274"),
                    new Claim(ClaimTypes.Country,"Iran"),
                    new Claim(ClaimTypes.Webpage,"https://SinjulMSBH.ir"),
                };

                byte[] secretKey = Encoding.UTF8.GetBytes("thisKeyIs32CharactersLong1234567");
                SigningCredentials signingCredentials =
                    new SigningCredentials(
                        new SymmetricSecurityKey(secretKey),
                            SecurityAlgorithms.HmacSha256Signature)
                ;

                byte[] encryptionkey = Encoding.UTF8.GetBytes("SinjulMSBHJack_4");
                EncryptingCredentials encryptingCredentials = new EncryptingCredentials(
                    new SymmetricSecurityKey(encryptionkey),
                       SecurityAlgorithms.Aes128KW,
                          SecurityAlgorithms.Aes128CbcHmacSha256
                );

                //JwtSecurityToken tokenn = new JwtSecurityToken(
                //    issuer: "SinjulMSBH",
                //    audience: "SinjulMSBH",
                //    expires: DateTime.Now.AddHours(3),
                //    claims: authClaims,
                //    signingCredentials: signingCredentials
                ////encryptingCredentials: encryptingCredentials,
                ////authClaims: authClaims,
                ////encryptionkey: encryptionkey,
                ////secretKey: secretKey,
                ////user: user
                //);

                //var token = new SecurityTokenDescriptor
                //{
                //    Issuer = "https://sinjulmsbh.ir",
                //    Audience = "https://sinjulmsbh.ir",
                //    IssuedAt = DateTime.Now,
                //    Expires = DateTime.Now.AddMinutes(60),
                //    NotBefore = DateTime.Now.AddMinutes(0),
                //    Subject = new ClaimsIdentity(authClaims),
                //    SigningCredentials = signingCredentials,
                //    //EncryptingCredentials = encryptingCredentials,
                //    //EncryptingCredentials = new X509EncryptingCredentials(new X509Certificate2("key_public.cer"))
                //    //EncryptingCredentials = new X509EncryptingCredentials(new X509Certificate2(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")))
                //};

                //var tk = new JwtSecurityTokenHandler();
                //var tk2 = tk.WriteToken(tokenn);
                //var deress = tk.ValidateToken(
                //    tk2,
                //    new TokenValidationParameters
                //    {
                //        ValidAudience = "https://sinjulmsbh.ir",
                //        ValidIssuer = "https://sinjulmsbh.ir",
                //        RequireSignedTokens = false,
                //    }
                //    , out SecurityToken securityTokenee
                //);

                //var tokenHandler = new JwtSecurityTokenHandler();
                //var securityToken = tokenHandler.CreateToken(token);
                //string encryptedJwt = tokenHandler.WriteToken(tokenn);


                //var jwt = tokenHandler.ReadJwtToken(encryptedJwt);
                //var ss = jwt.Claims.ToList();
                //var sss = new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims));
                //HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims));

                //var deres = tokenHandler.ValidateToken(
                //    encryptedJwt,
                //    new TokenValidationParameters
                //    {
                //        ValidAudience = "https://sinjulmsbh.ir",
                //        ValidIssuer = "https://sinjulmsbh.ir",
                //        RequireSignedTokens = false,
                //        //TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
                //    }
                //    , out SecurityToken securityTokene
                //);

                //Reading
                //install-package System.IdentityModel.Tokens.Jwt
                //string tokenE = tokenHandler.CreateEncodedJwt(token);
                //var handler = new JwtSecurityTokenHandler();
                //var claimsPrincipal = handler.ValidateToken(
                //    tokenE,
                //    new TokenValidationParameters
                //    {
                //        ValidAudience = "https://sinjulmsbh.ir",
                //        ValidIssuer = "https://sinjulmsbh.ir",
                //        RequireSignedTokens = false,
                //        TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
                //        //TokenDecryptionKey = new X509SecurityKey(new X509Certificate2("key_private.pfx", "idsrv3test"))
                //        //TokenDecryptionKey = new X509SecurityKey(new X509Certificate2(Encoding.UTF8.GetBytes("SinjulMSBHJack_4"), "SinjulMSBHJack_4"))
                //    },
                //    out SecurityToken securityTokenE);
                //var securityTokenMe = securityTokenE;

                //var securityToken = handler.CreateToken(
                //    new SecurityTokenDescriptor
                //    {
                //        //ValidateLifetime = true,
                //        //ValidateIssuerSigningKey = true,
                //        //ValidateIssuer = true,
                //        //ValidateAudience = true,
                //        //ValidateActor = true,
                //        //ValidateTokenReplay = true,
                //        //RequireSignedTokens = true,
                //        //RequireExpirationTime = true,
                //        //ClockSkew = TimeSpan.Zero,
                //        //ValidIssuer = "MyIssuer",
                //        //ValidAudience = "MyAudience",

                //        IssuedAt = DateTime.Now,
                //        Expires = DateTime.Now.AddMinutes(60),
                //        //Expires = DateTime.Now + TimeSpan.FromMinutes(30)
                //        NotBefore = DateTime.Now.AddMinutes(0),
                //        Issuer = "MyIssuer",
                //        Audience = "MyAudience",
                //        SigningCredentials =
                //        new SigningCredentials(
                //            new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),
                //                SecurityAlgorithms.HmacSha512Signature),
                //        Subject = new ClaimsIdentity(
                //            new[] {
                //                new Claim(ClaimTypes.NameIdentifier, user.Id),
                //                new Claim(ClaimTypes.Name, user.UserName),
                //                new Claim(ClaimTypes.Actor, "SinjulMSBH"),
                //                new Claim(ClaimTypes.Role,"Admin"),
                //                new Claim(ClaimTypes.MobilePhone,"09215899274"),
                //                new Claim(ClaimTypes.Country,"Iran"),
                //                new Claim(ClaimTypes.Webpage,"https://SinjulMSBH.ir"),
                //            }
                //        ),
                //        EncryptingCredentials = encryptingCredentials
                //    });


                JwtSecurityToken tokenn = new JwtSecurityToken(
                    "SinjulMSBH",
                    "SinjulMSBH",
                    authClaims,
                    DateTime.Now.AddMinutes(0),
                    DateTime.UtcNow.AddDays(4),
                    signingCredentials
                );

                var handler = new JwtSecurityTokenHandler();
                //// Save token
                string tt = handler.WriteToken(tokenn);

                var jwt1 = handler.ReadToken(tt);
                var jwt = handler.ReadJwtToken(tt);
                var ss = jwt.Claims.ToList();
                var sss = new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims));
                HttpContext.User = sss;

                //ValidateToken(tt);
                //VerifyToken(tt);

                //var deres = handler.ValidateToken(
                //    tt,
                //    new TokenValidationParameters
                //    {
                //        ValidAudience = "MyAudience",
                //        ValidIssuer = "MyIssuer",
                //        RequireSignedTokens = false,
                //        //TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
                //    }
                //    , out SecurityToken securityTokene
                //);

                //var secretKey2 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("a secret that needs to be at least 16 characters long"));
                //var claims = new Claim[] {
                //    new Claim(ClaimTypes.Name, "John"),
                //    new Claim(JwtRegisteredClaimNames.Email, "john.doe@blinkingcaret.com")
                //};
                //var token = new JwtSecurityToken(
                //    issuer: "your app",
                //    audience: "the client of your app",
                //    claims: claims,
                //    notBefore: DateTime.Now,
                //    expires: DateTime.Now.AddDays(28),
                //    signingCredentials: new SigningCredentials(
                //        new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),
                //        SecurityAlgorithms.HmacSha256
                //    )
                //);

                //var token2 = new JwtSecurityToken(new JwtHeader(new SigningCredentials(
                //    new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),
                //    SecurityAlgorithms.HmacSha256)), new JwtPayload(claims)
                //);
                //var claims2 = new Claim[] {
                //    new Claim(ClaimTypes.Name, "John"),
                //    new Claim(JwtRegisteredClaimNames.Email, "john.doe@blinkingcaret.com"),
                //    new Claim(JwtRegisteredClaimNames.Exp, $"{new DateTimeOffset(DateTime.Now.AddDays(1)).ToUnixTimeSeconds()}"),
                //    new Claim(JwtRegisteredClaimNames.Nbf, $"{new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds()}")
                //};

                //string jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

                return Ok(new
                {
                    token = tt,
                    validFrom = tokenn.ValidFrom,
                    validTo = tokenn.ValidTo
                    //getUsersAndClaims = $"http://localhost:5000/UsersAndClaimsView/{tt}"
                });
            }
            return Unauthorized();
        }

        public ClaimsPrincipal GetClaimsPrincipal(string tokenString)
        {
            var validationParameters = new TokenValidationParameters()
            {
                ValidAudience = "SinjulMSBH",
                ValidIssuer = "SinjulMSBH",
                //ValidateIssuerSigningKey = true,
                //ValidateIssuer = true,
                //ValidateAudience = true,
                //ValidateLifetime = true,
                //ClockSkew = TimeSpan.Zero,
                //ValidateActor = true,
                //ValidateTokenReplay = true,
                //RequireExpirationTime = true,
                //TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),
                RequireSignedTokens = false
            };

            SecurityToken token = new JwtSecurityToken();
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(tokenString, validationParameters, out token);

            return principal;
        }

        public bool ValidateToken(string tokenString)
        {
            var validationParameters = new TokenValidationParameters()
            {
                ValidAudience = "MyAudience",
                ValidIssuer = "MyIssuer",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),
                RequireSignedTokens = false,
            };

            SecurityToken token = new JwtSecurityToken();
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(tokenString, validationParameters, out token);

            return principal != null;
        }
        public static bool VerifyToken(string token)
        {
            var validationParameters = new TokenValidationParameters()
            {
                ValidAudience = "MyAudience",
                ValidIssuer = "MyIssuer",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken = null;
            try
            {
                tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
                var s = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken2);
            }
            catch (SecurityTokenException)
            {
                return false;
            }
            catch (Exception e)
            {
                //log(e.ToString()); //something else happened
                throw;
            }
            //... manual validations return false if anything untoward is discovered
            return validatedToken != null;
        }


        private string GenerateJWT()
        {
            var issuer = "https://sinjulmsbh.ir";//_config["Jwt:Issuer"];
            var audience = "https://sinjulmsbh.ir";//_config["Jwt:Audience"];
            //_config["Jwt:Key"]

            var expiry = DateTime.Now.AddMinutes(120);
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SecureKey"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials
            );

            string stringToken = new JwtSecurityTokenHandler().WriteToken(token);

            return stringToken;
        }

        private bool ValidateUser(LoginModel loginDetails) =>
            loginDetails.Username == "User1" && loginDetails.Password == "pass$word";


        [HttpPost]
        public IActionResult Login2([FromBody]LoginModel loginDetails)
        {
            bool result = ValidateUser(loginDetails);
            if (result)
            {
                string tokenString = GenerateJWT();
                return Ok(new { token = tokenString });
            }
            else
            {
                return Unauthorized();
            }
        }







        public async Task<IActionResult> Login2()
        {
            using var reader = new StreamReader(Request.Body);
            string body = await reader.ReadToEndAsync();
            //var cred = JsonConvert.DeserializeObject<Credentials>(body);
            //var result = (await userService.LoginUser(cred.userName, cred.password));
            int result = 200;
            if (result == 200)
            {
                var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Secrets"));
                var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256Signature);

                //var roles = await userService.GetRoleFromUsername(cred.userName);
                //var rolesString = JsonConvert.SerializeObject(roles);

                var tokeOptions = new JwtSecurityToken(
                            issuer: "http://localhost:44352",
                            audience: "http://localhost:44352",
                            claims: new List<Claim>(new List<Claim> {
                                        new Claim("userName",/*cred.userName*/ "User1"),
                                //new Claim("roles", rolesString)
                                //new Claim(ClaimTypes.Role, "Admin")
                                //new Claim(ClaimTypes.Role, rolesString1),
                                //new Claim(ClaimTypes.Role, rolesString2),
                                //new Claim(ClaimTypes.Role, rolesString3)
                            }),
                            expires: DateTime.Now.AddHours(1),
                            signingCredentials: signinCredentials
                );
            }

            return Unauthorized();
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        public IActionResult AddVideo()
        {
            using var reader = new StreamReader(Request.Body);
            return Ok();
        }

        private string BuildToken(UserModel user)
        {

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, user.Name),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Birthdate, user.Birthdate.ToString("yyyy-MM-dd")),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(""));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
              "",
              "",
              claims,
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private class UserModel
        {
            public string Name { get; internal set; }
            public string Email { get; internal set; }
            public DateTime Birthdate { get; internal set; }
        }
    }
}
