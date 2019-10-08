using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Simple.Controllers
{
    //ApiController attribute
    //The [ApiController] attribute can be applied to a controller class to enable the following opinionated, API-specific behaviors:
    //Attribute routing requirement
    //Automatic HTTP 400 responses
    //Binding source parameter inference
    //Multipart/form-data request inference
    //Problem details for error status codes
    //These features require a compatibility version of 2.1 or later.
    [ApiController]
    //Attribute on multiple controllers
    [Produces(MediaTypeNames.Application.Json)]
    //The[ApiController] attribute makes attribute routing a requirement.For example:
    //Actions are inaccessible via conventional routes defined by UseEndpoints, UseMvc, or UseMvcWithDefaultRoute in Startup.Configure.
    //https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/routing?view=aspnetcore-3.0#conventional-routing
    [Route("[controller]")]
    //if you plan to use the same controller for both views and web APIs, derive it from Controller.
    //[Microsoft.AspNetCore.Mvc.Controller]
    //public abstract class ControllerBase
    //[ControllerAttribute]
    //https://docs.microsoft.com/en-gb/dotnet/api/microsoft.aspnetcore.mvc.controllerbase?view=aspnetcore-2.2&viewFallbackFrom=aspnetcore-3.0
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [HttpGet]
        public ActionResult<int> GetById(int id)
        {
            return 1;
        }

        [HttpPost]
        //HttpDeleteAttribute
        //HttpGetAttribute
        //HttpHeadAttribute
        //HttpOptionsAttribute
        //HttpPatchAttribute
        //HttpPostAttribute
        //HttpPutAttribute
        //[Route] Specifies URL pattern for a controller or action.
        //[Bind] Specifies prefix and properties to include for model binding.
        //[HttpGet] Identifies an action that supports the HTTP GET action verb.
        //[Consumes] Specifies data types that an action accepts.
        //[Produces] Specifies data types that an action returns.
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public ActionResult<WeatherForecast> Create(WeatherForecast weatherForecast)
        {
            //pet.Id = _petsInMemoryStore.Any() ? _petsInMemoryStore.Max(p => p.Id) + 1 : 1;
            //_petsInMemoryStore.Add(pet);

            //For a list that includes the available attributes, see the Microsoft.AspNetCore.Mvc namespace.
            //https://docs.microsoft.com/dotnet/api/microsoft.aspnetcore.mvc
            //return new EmptyResult();
            //return Accepted() AcceptedAtActionResult
            //return BadRequest BadRequestResult BadRequestObjectResult
            //return Forbid ForbidResult
            //return JsonResult JsonResult
            //return Ok OkResult OkObjectResult
            return CreatedAtAction(nameof(GetById), new { id = weatherForecast.Id }, weatherForecast);
        }
    }
}
