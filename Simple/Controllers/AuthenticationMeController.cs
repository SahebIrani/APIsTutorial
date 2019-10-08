using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

using Simple.Models;
using Simple.Services;

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
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ModelStateDictionary), StatusCodes.Status400BadRequest)]
        [ProducesDefaultResponseType]
        public IActionResult RequestToken([FromBody] TokenRequest request)
        {
            //if (!ModelState.IsValid)
            //    return BadRequest(ModelState);

            if (AuthenticateService.IsAuthenticated(request, out string token))
                return Ok(token);

            return BadRequest("Invalid Request");
        }
    }
}
