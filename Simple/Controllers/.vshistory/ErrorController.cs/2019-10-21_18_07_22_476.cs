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
        [HttpGet("/error")] public IActionResult Error() => Problem();

        [HttpGet("/error-local-development")]
        public IActionResult ErrorLocalDevelopment([FromServices] IWebHostEnvironment webHostEnvironment)
        {
            if (!webHostEnvironment.IsDevelopment()) //EnvironmentName != "Development"
                throw new InvalidOperationException("This shouldn't be invoked in non-development environments .. !!!!");

            IExceptionHandlerFeature context = HttpContext.Features.Get<IExceptionHandlerFeature>();
            Exception exception = HttpContext.Features.Get<IExceptionHandlerFeature>().Error;

            return Problem(
                detail: exception.StackTrace,
                title: exception.Message,
                type: exception.GetType().Name,
                statusCode: Response.StatusCode,
                instance: Request.Path
            );
        }
    }
}
