using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Sample.Models;

using Simple.Models;

namespace Simple.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationMeController : ControllerBase
    {
        public AuthenticationMeController(IAuthenticateService authenticateService) => AuthenticateService = authenticateService;
        public IAuthenticateService AuthenticateService { get; }

        [AllowAnonymous]
        [HttpPost, Route("request")]
        public IActionResult RequestToken([FromBody] TokenRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (AuthenticateService.IsAuthenticated(request, out string token))
                return Ok(token);

            return BadRequest("Invalid Request");
        }
    }
}
