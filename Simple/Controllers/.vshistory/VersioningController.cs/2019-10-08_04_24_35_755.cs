///api/v[1|2|3]/helloworld
//[ApiVersion("1.0")]
//[Route("api/v{version:apiVersion}/[controller]")]
//public class HelloWorldController : Controller
//{
//    public string Get() => "Hello world!";
//}

//[ApiVersion("2.0")]
//[ApiVersion("3.0")]
//[Route("api/v{version:apiVersion}/helloworld")]
//public class HelloWorld2Controller : Controller
//{
//    [HttpGet]
//    public string Get() => "Hello world v2!";

//    [HttpGet, MapToApiVersion("3.0")]
//    public string GetV3() => "Hello world v3!";
//}

//[ApiVersion("2.0")]
//[ApiVersion("1.0", Deprecated = true)]

//[ApiVersion("1")]
//[ApiVersion("2.0")]
///api/helloworld?api-version=2.0
//[Route("api/v{version:apiVersion}/[controller]")]

//[ApiVersion("2.0")]
//[ApiVersion("3.0")]
//[Route("api/v{version:apiVersion}/helloworld")]


//namespace Simple.Controllers
//{
//    using Microsoft.AspNetCore.Mvc;

//    [ApiController]
//    [ApiVersion("1.0")]
//    [Route("api/v{version:apiVersion}/[controller]")]
//    public class HelloWorldController : ControllerBase
//    {
//        // GET api/v{version}/helloworld
//        [HttpGet]
//        public IActionResult Get(ApiVersion apiVersion) => Ok(new { Controller = GetType().Name, Version = apiVersion.ToString() });

//        // GET api/v{version}/helloworld/{id}
//        [HttpGet("{id:int}")]
//        public IActionResult Get(int id, ApiVersion apiVersion) => Ok(new { Controller = GetType().Name, Id = id, Version = apiVersion.ToString() });

//        // POST api/v{version}/helloworld
//        [HttpPost]
//        public IActionResult Post(ApiVersion apiVersion) => CreatedAtAction(nameof(Get), new { id = 42, version = apiVersion.ToString() }, null);
//    }

//    [ApiController]
//    [ApiVersion("1.0")]
//    [Route("api/[controller]")]
//    public class ValuesController : ControllerBase
//    {
//        // GET api/values?api-version=1.0
//        [HttpGet]
//        public string Get(ApiVersion apiVersion) => $"Controller = {GetType().Name}\nVersion = {apiVersion}";
//    }

//    [ApiController]
//    [ApiVersion("2.0")]
//    [Route("api/values")]
//    public class Values2Controller : ControllerBase
//    {
//        // GET api/values?api-version=2.0
//        [HttpGet]
//        public string Get(ApiVersion apiVersion) => $"Controller = {GetType().Name}\nVersion = {apiVersion}";
//    }
//}
