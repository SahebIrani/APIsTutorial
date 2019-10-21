using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

using Simple.Exceptions;

namespace Simple.Filters
{
    public class HttpResponseExceptionFilter : IActionFilter, IOrderedFilter
    {
        public int Order { get; set; } = int.MaxValue - 10;

        public void OnActionExecuting(ActionExecutingContext context) { }

        public void OnActionExecuted(ActionExecutedContext context)
        {
            if (context.Exception is HttpResponseException exception)
            {
                context.Result = new ObjectResult(exception.Value) { StatusCode = exception.Status };
                context.HttpContext.Response.WriteAsync(exception.Message)/*.GetAwaiter().GetResult()*/;
                context.ExceptionHandled = true;
            }
        }
    }
}
