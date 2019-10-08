using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Simple.Middlewares
{
    public sealed class JwtMiddleware
    {
        public JwtMiddleware(RequestDelegate next) => _next = next;

        private static readonly string Bearer = "bearer";
        private readonly JwtSecurityTokenHandler _handler = new JwtSecurityTokenHandler();
        private readonly RequestDelegate _next;

        public async Task Invoke(HttpContext context)
        {
            string token = context.Request.Headers[HeaderNames.Authorization].ToString();
            if (!token.ToLower().StartsWith(Bearer))
                throw new InvalidOperationException(string.Format("Expected {0} at the start of the token.", Bearer));

            var jwt = _handler.ReadJwtToken(token.Substring(Bearer.Length).TrimStart());
            context.User = new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims));

            await _next(context);
        }
    }
}
