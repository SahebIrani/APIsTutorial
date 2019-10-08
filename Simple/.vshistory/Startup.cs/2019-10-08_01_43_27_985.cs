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
using Microsoft.AspNetCore.Mvc.Formatters;
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

            services.AddControllers(options =>
            {
                //Browsers and content negotiation
                //Unlike typical API clients, web browsers supply Accept headers. Web browser specify many formats, including wildcards. By default, when the framework detects that the request is coming from a browser:

                //The Accept header is ignored.
                //The content is returned in JSON, unless otherwise configured.
                //This provides a more consistent experience across browsers when consuming APIs.

                //To configure an app to honor browser accept headers, set RespectBrowserAcceptHeader to true:
                options.RespectBrowserAcceptHeader = true; // false by default

                //Special case formatters
                //Some special cases are implemented using built-in formatters.By default, string return types are formatted as text / plain(text / html if requested via the Accept header).This behavior can be deleted by removing the TextOutputFormatter. Formatters are removed in the Configure method.Actions that have a model object return type return 204 No Content when returning null.This behavior can be deleted by removing the HttpNoContentOutputFormatter. The following code removes the TextOutputFormatter and HttpNoContentOutputFormatter.
                // requires using Microsoft.AspNetCore.Mvc.Formatters;

                //Without the TextOutputFormatter, string return types return 406 Not Acceptable. If an XML formatter exists, it formats string return types if the TextOutputFormatter is removed.
                //Without the HttpNoContentOutputFormatter, null objects are formatted using the configured formatter.For example:
                //The JSON formatter returns a response with a body of null.
                //The XML formatter returns an empty XML element with the attribute xsi:nil = "true" set.
                options.OutputFormatters.RemoveType<TextOutputFormatter>();
                options.OutputFormatters.RemoveType<HttpNoContentOutputFormatter>();
            })
                 //Add Newtonsoft.Json - based JSON format support
                 //Microsoft.AspNetCore.Mvc.NewtonsoftJson
                 //Prior to ASP.NET Core 3.0, the default used JSON formatters implemented using the Newtonsoft.Json package. In ASP.NET Core 3.0 or later, the default JSON formatters are based on System.Text.Json.Support for Newtonsoft.Json based formatters and features is available by installing the Microsoft.AspNetCore.Mvc.NewtonsoftJson NuGet package and configuring it in Startup.ConfigureServices.
                 //Uses Newtonsoft.Json attributes. For example, [JsonProperty] or[JsonIgnore].
                 //Features for the Newtonsoft.Json - based formatters can be configured using Microsoft.AspNetCore.Mvc.MvcNewtonsoftJsonOptions.SerializerSettings:
                 //.AddNewtonsoftJson(options =>
                 //{
                 //    // Use the default property (Pascal) casing
                 //    options.SerializerSettings.ContractResolver = new DefaultContractResolver();

                 //    // Configure a custom converter
                 //    options.SerializerOptions.Converters.Add(new MyCustomJsonConverter());
                 //})

                 //Add XML format support
                 //XML formatters implemented using XmlSerializer are configured by calling AddXmlSerializerFormatters:
                 //The preceding code serializes results using XmlSerializer.
                 //When using the preceding code, controller methods should return the appropriate format based on the request's Accept header.
                 //.AddXmlOptions(opts => { })
                 .AddXmlSerializerFormatters()
                .AddXmlDataContractSerializerFormatters()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.WriteIndented = true;

                    // Use the default property (Pascal) casing.
                    options.JsonSerializerOptions.PropertyNamingPolicy = null;

                    // Configure a custom converter.
                    //options.JsonSerializerOptions.Converters.Add(new MyCustomJsonConverter());
                })
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
