using System;
using System.Net;

namespace Simple.Exceptions
{
    public class HttpResponseException : Exception
    {
        public int Status { get; set; } = (int)HttpStatusCode.InternalServerError;

        public object Value { get; set; }

        public HttpResponseException()
        {
        }

        public HttpResponseException(string message) : base(message)
        {
        }

        public HttpResponseException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
