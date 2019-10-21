using System;

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;

namespace Simple.Controllers
{
    //[ApiController] // Global
    public class ErrorController : ControllerBase
    {
        [Route("/error")] public IActionResult Error() => Problem();

        [Route("/error-local-development")]
        public IActionResult ErrorLocalDevelopment([FromServices] IWebHostEnvironment webHostEnvironment)
        {
            if (!webHostEnvironment.IsDevelopment()) //EnvironmentName != "Development"
                throw new InvalidOperationException("This shouldn't be invoked in non-development environments .. !!!!");

            IExceptionHandlerFeature context = HttpContext.Features.Get<IExceptionHandlerFeature>();

            return Problem(
                detail: context.Error.StackTrace,
                title: context.Error.Message,
                statusCode: Response.StatusCode);
        }
    }
}
