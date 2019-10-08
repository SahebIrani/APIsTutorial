using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using Simple.Models;

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

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        private readonly ILogger<WeatherForecastController> _logger;

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
        public ActionResult<WeatherForecast> GetById(int id)
        {
            var weatherForecast = Get().SingleOrDefault(c => c.Id == id);
            return weatherForecast;
        }

        //Without the[ApiController] attribute or binding source attributes like[FromQuery], the ASP.NET Core runtime attempts to use the complex object model binder.The complex object model binder pulls data from value providers in a defined order.
        //In the following example, the[FromQuery] attribute indicates that the discontinuedOnly parameter value is provided in the request URL's query string:
        [HttpGet]
        public ActionResult<List<TodoItem>> Get([FromQuery] bool discontinuedOnly = false)
        {
            List<TodoItem> products = null;

            if (discontinuedOnly)
            {
                //products = _productsInMemoryStore.Where(p => p.IsDiscontinued).ToList();
            }
            else
            {
                //products = _productsInMemoryStore;
            }

            return products;
        }

        //FromBody inference notes
        //[FromBody] isn't inferred for simple types such as string or int. Therefore, the [FromBody] attribute should be used for simple types when that functionality is needed.
        //When an action has more than one parameter bound from the request body, an exception is thrown.For example, all of the following action method signatures cause an exception:
        //[FromBody] inferred on both because they're complex types.
        //[HttpPost]
        //public IActionResult Action1(Product product, Order order)
        //[HttpPost]
        //public IActionResult Action2(Product product, [FromBody] Order order)
        //[HttpPost]
        //public IActionResult Action3([FromBody] Product product, [FromBody] Order order)

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
        //A binding source attribute defines the location at which an action parameter's value is found. The following binding source attributes exist:
        //Attribute Binding source
        //[FromBody] Request body
        //[FromForm] Form data in the request body
        //[FromHeader] Request header
        //[FromQuery] Request query string parameter
        //[FromRoute] Route data from the current request
        //[FromServices]  The request service injected as an action parameter
        //Binding source parameter inference
        //Warning
        //Don't use [FromRoute] when values might contain %2f (that is /). %2f won't be unescaped to /. Use[FromQuery] if the value might contain %2f.
        public ActionResult<WeatherForecast> Create([FromBody] WeatherForecast weatherForecast)
        {
            //pet.Id = _petsInMemoryStore.Any() ? _petsInMemoryStore.Max(p => p.Id) + 1 : 1;
            //_petsInMemoryStore.Add(pet);

            //Automatic HTTP 400 responses
            //The[ApiController] attribute makes model validation errors automatically trigger an HTTP 400 response.Consequently, the following code is unnecessary in an action method:
            //ASP.NET Core MVC uses the ModelStateInvalidFilter action filter to do the preceding check.
            //https://docs.microsoft.com/en-gb/dotnet/api/microsoft.aspnetcore.mvc.infrastructure.modelstateinvalidfilter?view=aspnetcore-2.2
            if (!ModelState.IsValid) return BadRequest(ModelState);

            //Default BadRequest response
            //The ValidationProblemDetails type:
            //Provides a machine - readable format for specifying errors in web API responses.
            //  Complies with the RFC 7807 specification.
            //https://tools.ietf.org/html/rfc7807
            //With a compatibility version of 2.2 or later, the default response type for an HTTP 400 response is ValidationProblemDetails.The following request body is an example of the serialized type:
            //https://docs.microsoft.com/en-gb/dotnet/api/microsoft.aspnetcore.mvc.validationproblemdetails?view=aspnetcore-2.2
            //{
            //    "": [
            //      "A non-empty request body is required."
            //    ]
            //}

            //{
            //  "type": "https://tools.ietf.org/html/rfc7231#section-6.5.1",
            //  "title": "One or more validation errors occurred.",
            //  "status": 400,
            //  "traceId": "|7fb5e16a-4c8f23bbfc974667.",
            //  "errors": {
            //    "": [
            //      "A non-empty request body is required."
            //    ]
            //}
            //}

            //Log automatic 400 responses
            //https://github.com/aspnet/AspNetCore.Docs/issues/12157

            //Disable automatic 400 response
            //To disable the automatic 400 behavior, set the SuppressModelStateInvalidFilter property to true.Add the following highlighted code in Startup.ConfigureServices:
            //https://docs.microsoft.com/dotnet/api/microsoft.aspnetcore.mvc.apibehavioroptions.suppressmodelstateinvalidfilter#Microsoft_AspNetCore_Mvc_ApiBehaviorOptions_SuppressModelStateInvalidFilter



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
