using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

using Simple.Data;
using Simple.Models;
using Simple.Services;

//Attribute on an assembly
//If compatibility version is set to 2.2 or later, the[ApiController] attribute can be applied to an assembly.Annotation in this manner applies web API behavior to all controllers in the assembly. There's no way to opt out for individual controllers. Apply the assembly-level attribute to the namespace declaration surrounding the Startup class:
[assembly: ApiController]
namespace Simple
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                //options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"))
                options.UseInMemoryDatabase("SinjulMSBH")
            );

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.AddScoped<IAuthenticateService, TokenAuthenticationService>();
            services.AddScoped<IUserManagementService, UserManagementService>();

            IdentityModelEventSource.ShowPII = true;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            services.Configure<TokenManagement>(Configuration.GetSection(nameof(TokenManagement)));
            TokenManagement token = Configuration.GetSection(nameof(TokenManagement)).Get<TokenManagement>();
            byte[] secret = Encoding.ASCII.GetBytes(token.Secret);
            byte[] decryptionKey = Encoding.ASCII.GetBytes(token.Encrypt);

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

                //    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                //    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //    //options.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
                //    //options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                //    //options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
                //    //options.DefaultSignOutScheme = JwtBearerDefaults.AuthenticationScheme;
                //    //options.RequireAuthenticatedSignIn = true;

            })
            .AddCookie("cookie", cfg => cfg.SlidingExpiration = true)
            .AddJwtBearer("jwt", options =>
            {
                options.SecurityTokenValidators.Clear();
                //options.SecurityTokenValidators.Add((ISecurityTokenValidator)new googletokenvalidator());

                options.RequireHttpsMetadata = false;
                options.SaveToken = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    //TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
                    //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
                    //TokenDecryptionKey = new X509SecurityKey(new X509Certificate2("key_private.pfx", "idsrv3test")),
                    //TokenDecryptionKey = new X509SecurityKey(new X509Certificate2(Encoding.UTF8.GetBytes("SinjulMSBHJack_4"), "SinjulMSBHJack_4")),
                    //ValidIssuer = Configuration["Jwt:Issuer"],
                    //ValidAudience = Configuration["Jwt:Audience"],
                    //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))

                    ValidateLifetime = true, //validate the expiration and not before values in the token
                    //ClockSkew = TimeSpan.Zero,
                    //ClockSkew = TimeSpan.FromMinutes(0)
                    ClockSkew = TimeSpan.FromMinutes(5.0), //5 minute tolerance for the expiration date

                    RequireSignedTokens = true,
                    RequireExpirationTime = true,
                    ValidateActor = false,
                    ValidateIssuerSigningKey = true,
                    ValidateTokenReplay = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(secret),
                    TokenDecryptionKey = new SymmetricSecurityKey(decryptionKey),
                    ValidIssuer = token.Issuer,
                    ValidAudience = token.Audience,
                };

                options.Validate();

                //options.Authority = domain;
                //options.Audience = Configuration["Auth0:Audience"];
                //options.Authority = "https://offishopp.auth0.com/";
                //options.Audience = "https://localhost:5001";

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = async context =>
                    {
                        ((ILogger)context.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                  .CreateLogger(nameof(JwtBearerEvents)))
                                    .LogError((string)"SinjulMSBH / Access denied! Please login with an account which has enough permissions first .. !!!!", context.Exception);

                        if (context.Exception != null)
                        {
                            context.HttpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                            await context.HttpContext.Response.WriteAsync((string)"SinjulMSBH / Access denied! Please login with an account which has enough permissions first .. !!!!");
                        }
                    }
                };

                options.Events.OnMessageReceived = context =>
                {
                    string unencryptedToken = context.Token;
                    string encryptedToken = /*Decrypt(unencryptedToken)*/"SinjulMSBH_encryptedToken";
                    context.Token = encryptedToken;
                    return Task.CompletedTask;
                };

                options.Events.OnTokenValidated = async ctx =>
                {
                    string oid = ctx.Principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");
                    var db = ctx.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
                    bool isSuperAdmin = /*await db.SuperAdmins.AnyAsync(a => a.ObjectId == oid)*/ true;
                    if (isSuperAdmin)
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Role, "superadmin")
                        };
                        var appIdentity = new ClaimsIdentity(claims);
                        ctx.Principal.AddIdentity(appIdentity);
                    }
                };
            });

            //[Authorize(Policy = "Over18")]
            //[Authorize(Policy = ...., AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
            // Or
            //[Authorize(Policy = ...., AuthenticationSchemes =
            //CookieAuthenticationDefaults.AuthenticationScheme + ", " + JwtBearerDefaults.AuthenticationScheme)]
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Over18", policy =>
                {
                    policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    //policy.Requirements.Add(new MinimumAgeRequirement());
                });
            });

            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder.AllowAnyOrigin()
                      .AllowAnyMethod()
                      .AllowAnyHeader()
                      .AllowCredentials()
                .Build());
            });

            services.AddControllers()
                .AddXmlSerializerFormatters()
                .AddXmlDataContractSerializerFormatters()
                .AddXmlOptions(opts => { })
                .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true)
                .ConfigureApiBehaviorOptions(options =>
                {
                    //Multipart / form - data request inference
                    //The[ApiController] attribute applies an inference rule when an action parameter is annotated with the[FromForm] attribute.The multipart/ form - data request content type is inferred.
                    //To disable the default behavior
                    options.SuppressConsumesConstraintForFormFileParameters = true;
                    //Disable inference rules || To disable binding source inference
                    options.SuppressInferBindingSourcesForParameters = true;
                    //Disable automatic 400 response
                    options.SuppressModelStateInvalidFilter = true;
                    //Problem details for error status codes
                    //When the compatibility version is 2.2 or later, MVC transforms an error result(a result with status code 400 or higher) to a result with ProblemDetails.The ProblemDetails type is based on the RFC 7807 specification for providing machine-readable error details in an HTTP response.
                    //https://tools.ietf.org/html/rfc7807
                    //Consider the following code in a controller action:
                    //if (pet == null)
                    //{
                    //    return NotFound();
                    //}
                    //The NotFound method produces an HTTP 404 status code with a ProblemDetails body. For example:
                    //{
                    //      type: "https://tools.ietf.org/html/rfc7231#section-6.5.4",
                    //      title: "Not Found",
                    //      status: 404,
                    //      traceId: "0HLHLV31KRN83:00000001"
                    //}
                    //Disable ProblemDetails response
                    //The automatic creation of a ProblemDetails instance is disabled
                    options.SuppressMapClientErrors = true;
                    options.ClientErrorMapping[404].Link = "https://httpstatuses.com/404";
                })
           ;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                //app.UseDatabaseErrorPage();
            }
            else
            {
                //app.UseExceptionHandler("/Home/Error");
                //app.UseHsts();
            }

            //SeedDB.Initialize(app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope().ServiceProvider);

            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.UseHttpsRedirection();

            app.UseRouting();

            //app.UseCors("CorsPolicy");
            app.UseCors(x => x.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

            //app.UseMiddleware<JwtMiddleware>();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
