using System;
using System.Net;

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;

using Newtonsoft.Json;

namespace Simple.Controllers
{
    //[ApiController] // Global
    public class ErrorController : ControllerBase
    {
        [HttpGet(nameof(MyException))] public IActionResult MyException() { };
        [HttpGet("/error")] public IActionResult Error() => Problem();

        [HttpGet("/error-local-development")]
        public IActionResult ErrorLocalDevelopment([FromServices] IWebHostEnvironment webHostEnvironment)
        {
            if (!webHostEnvironment.IsDevelopment()) //EnvironmentName != "Development"
                throw new InvalidOperationException("This shouldn't be invoked in non-development environments .. !!!!");

            IExceptionHandlerFeature context = HttpContext.Features.Get<IExceptionHandlerFeature>();
            Exception exception = HttpContext.Features.Get<IExceptionHandlerFeature>().Error;

            string errorDetails = $@"{exception.Message}{Environment.NewLine}{exception.StackTrace}";
            int statusCode = (int)HttpStatusCode.InternalServerError;
            ProblemDetails problemDetails = new ProblemDetails
            {
                Title = exception.Message,
                Status = statusCode,
                Detail = exception.StackTrace,
                Instance = Guid.NewGuid().ToString(),
            };
            string json = JsonConvert.SerializeObject(problemDetails);

            return Problem(
                detail: exception.StackTrace,
                title: exception.Message,
                type: context.GetType().Name,
                statusCode: Response.StatusCode,
                instance: Request.Path
            );
        }
    }
}
