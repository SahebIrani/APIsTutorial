namespace Simple.Services.vshistory.IAuthenticateService.cs
{
    public interface IAuthenticateService
    {
        bool IsAuthenticated(TokenRequest request, out string token);
    }
}
