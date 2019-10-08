namespace Simple.V1.Controllers.vshistory.OrdersController.cs
{
    using Microsoft.AspNetCore.Mvc;

    [ApiController]
    [Route("[controller]")]
    [Route("v{version:apiVersion}/[controller]")]
    public class OrdersController : ControllerBase
    {
        // GET ~/v1/orders/{accountId}
        // GET ~/orders/{accountId}?api-version=1.0
        [HttpGet("{accountId}")]
        [ApiVersion("1", Deprecated = true)]
        public IActionResult Get(string accountId, ApiVersion apiVersion) => Ok(new Order(GetType().FullName, accountId, apiVersion.ToString()));
    }
}
