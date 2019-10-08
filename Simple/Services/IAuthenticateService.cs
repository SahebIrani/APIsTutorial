using Simple.Models;

namespace Simple.Services
{
    public interface IAuthenticateService
    {
        bool IsAuthenticated(TokenRequest request, out string token);
    }
}
