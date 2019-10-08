using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Simple.Controllers
{
    [ApiController]
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

        //[HttpPost]
        //[ProducesResponseType(StatusCodes.Status201Created)]
        //[ProducesResponseType(StatusCodes.Status400BadRequest)]
        //public ActionResult<Pet> Create(Pet pet)
        //{
        //    pet.Id = _petsInMemoryStore.Any() ?
        //             _petsInMemoryStore.Max(p => p.Id) + 1 : 1;
        //    _petsInMemoryStore.Add(pet);

        //    return CreatedAtAction(nameof(GetById), new { id = pet.Id }, pet);
        //}
    }
}
