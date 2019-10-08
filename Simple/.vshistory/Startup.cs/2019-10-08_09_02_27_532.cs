using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Reflection;
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
using Microsoft.AspNetCore.Mvc.Versioning.Conventions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

using Simple.Data;
using Simple.Filters;
using Simple.Models;
using Simple.Services;

//Attribute on an assembly
//If compatibility version is set to 2.2 or later, the[ApiController] attribute can be applied to an assembly.Annotation in this manner applies web API behavior to all controllers in the assembly. There's no way to opt out for individual controllers. Apply the assembly-level attribute to the namespace declaration surrounding the Startup class:
//[assembly: ApiController]

//Microsoft.AspNetCore.Mvc.ApiConventionTypeAttribute applied to an assembly — Applies the specified convention type to all controllers in the current assembly.As a recommendation, apply assembly-level attributes in the Startup.cs file.
//In the following example, the default set of conventions is applied to all controllers in the assembly:
//[assembly: ApiConventionType(typeof(DefaultApiConventions))]
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

            // Register the Swagger generator, defining 1 or more Swagger documents
            //services.AddSwaggerGen(c =>
            //{
            //    c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });
            //});

            // Register the Swagger generator, defining 1 or more Swagger documents
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Version = "v1",
                    Title = "ToDo API",
                    Description = "A simple example ASP.NET Core Web API",
                    TermsOfService = new Uri("https://jackslater.ir/terms"),
                    Contact = new OpenApiContact
                    {
                        Name = "SinjulMSBH",
                        Email = string.Empty,
                        Url = new Uri("https://twitter.com/Sinjul_MSBH"),
                    },
                    License = new OpenApiLicense
                    {
                        Name = "Use under LICX",
                        Url = new Uri("https://jackslater.ir/license"),
                    }
                });

                // Set the comments path for the Swagger JSON and UI.
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);

            });


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
                //    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                //options.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultSignOutScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.RequireAuthenticatedSignIn = true;

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

            //services.AddCors(options =>
            //{
            //    options.AddPolicy("CorsPolicy",
            //        builder => builder.AllowAnyOrigin()
            //          .AllowAnyMethod()
            //          .AllowAnyHeader()
            //          .AllowCredentials()
            //    .Build());
            //});

            services.AddControllers(options =>
            {
                // the sample application always uses the latest version, but you may want an explicit version such as Version_2_2
                // note: Endpoint Routing is enabled by default; however, if you need legacy style routing via IRouter, change it to false
                options.EnableEndpointRouting = true;

                //Use exceptions to modify the response
                //The contents of the response can be modified from outside of the controller.In ASP.NET 4.x Web API, one way to do this was using the HttpResponseException type.ASP.NET Core doesn't include an equivalent type. Support for HttpResponseException can be added with the following steps:
                //Create a well - known exception type named HttpResponseException:
                options.Filters.Add(new HttpResponseExceptionFilter());

                //Browsers and content negotiation
                //Unlike typical API clients, web browsers supply Accept headers. Web browser specify many formats, including wildcards. By default, when the framework detects that the request is coming from a browser:

                //The Accept header is ignored.
                //The content is returned in JSON, unless otherwise configured.
                //This provides a more consistent experience across browsers when consuming APIs.

                //To configure an app to honor browser accept headers, set RespectBrowserAcceptHeader to true:
                //options.RespectBrowserAcceptHeader = true; // false by default

                //Special case formatters
                //Some special cases are implemented using built-in formatters.By default, string return types are formatted as text / plain(text / html if requested via the Accept header).This behavior can be deleted by removing the TextOutputFormatter. Formatters are removed in the Configure method.Actions that have a model object return type return 204 No Content when returning null.This behavior can be deleted by removing the HttpNoContentOutputFormatter. The following code removes the TextOutputFormatter and HttpNoContentOutputFormatter.
                // requires using Microsoft.AspNetCore.Mvc.Formatters;

                //Without the TextOutputFormatter, string return types return 406 Not Acceptable. If an XML formatter exists, it formats string return types if the TextOutputFormatter is removed.
                //Without the HttpNoContentOutputFormatter, null objects are formatted using the configured formatter.For example:
                //The JSON formatter returns a response with a body of null.
                //The XML formatter returns an empty XML element with the attribute xsi:nil = "true" set.

                //options.OutputFormatters.RemoveType<TextOutputFormatter>();
                //options.OutputFormatters.RemoveType<HttpNoContentOutputFormatter>();

                //options.InputFormatters.Insert(0, new VcardInputFormatter());
                //options.OutputFormatters.Insert(0, new VcardOutputFormatter());
            })
                 //Add Newtonsoft.Json - based JSON format support
                 //Microsoft.AspNetCore.Mvc.NewtonsoftJson
                 //Prior to ASP.NET Core 3.0, the default used JSON formatters implemented using the Newtonsoft.Json package. In ASP.NET Core 3.0 or later, the default JSON formatters are based on System.Text.Json.Support for Newtonsoft.Json based formatters and features is available by installing the Microsoft.AspNetCore.Mvc.NewtonsoftJson NuGet package and configuring it in Startup.ConfigureServices.
                 //Uses Newtonsoft.Json attributes. For example, [JsonProperty] or[JsonIgnore].
                 //Features for the Newtonsoft.Json - based formatters can be configured using Microsoft.AspNetCore.Mvc.MvcNewtonsoftJsonOptions.SerializerSettings:
                 //.AddNewtonsoftJson(options =>
                 //{
                 //    // Use the default property (Pascal) casing
                 //    //options.SerializerSettings.ContractResolver = new DefaultContractResolver();

                 //    // Configure a custom converter
                 //    //options.SerializerSettings.Converters.Add(new MyCustomJsonConverter());
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
                    //options.JsonSerializerOptions.WriteIndented = true;

                    // Use the default property (Pascal) casing.
                    //options.JsonSerializerOptions.PropertyNamingPolicy = null;

                    // Configure a custom converter.
                    //options.JsonSerializerOptions.Converters.Add(new MyCustomJsonConverter());
                })
                .ConfigureApiBehaviorOptions(options =>
                {
                    //Multipart / form - data request inference
                    //The[ApiController] attribute applies an inference rule when an action parameter is annotated with the[FromForm] attribute.The multipart/ form - data request content type is inferred.
                    //To disable the default behavior
                    //options.SuppressConsumesConstraintForFormFileParameters = true;
                    //Disable inference rules || To disable binding source inference
                    //options.SuppressInferBindingSourcesForParameters = true;
                    //Disable automatic 400 response
                    //options.SuppressModelStateInvalidFilter = true;
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
                    //options.SuppressMapClientErrors = true;

                    //Use ApiBehaviorOptions.ClientErrorMapping
                    //Use the ClientErrorMapping property to configure the contents of the ProblemDetails response. For example, the following code in Startup.ConfigureServices updates the type property for 404 responses:
                    //options.ClientErrorMapping[404].Link = "https://httpstatuses.com/404";

                    //Validation failure error response
                    //For web API controllers, MVC responds with a ValidationProblemDetails response type when model validation fails. MVC uses the results of InvalidModelStateResponseFactory to construct the error response for a validation failure.The following example uses the factory to change the default response type to SerializableError in Startup.ConfigureServices:
                    options.InvalidModelStateResponseFactory = context =>
                    {
                        // Get an instance of ILogger (see below) and log accordingly.
                        return new BadRequestObjectResult(context.ModelState);

                        //var result = new BadRequestObjectResult(context.ModelState);

                        // TODO: add `using using System.Net.Mime;` to resolve MediaTypeNames
                        //result.ContentTypes.Add(MediaTypeNames.Application.Json);
                        //result.ContentTypes.Add(MediaTypeNames.Application.Xml);

                        //return result;
                    };
                })
                .SetCompatibilityVersion(CompatibilityVersion.Latest)
           ;

            //Client error response
            //An error result is defined as a result with an HTTP status code of 400 or higher. For web API controllers, MVC transforms an error result to a result with ProblemDetails.
            //The error response can be configured in one of the following ways:
            //Implement ProblemDetailsFactory
            //Use ApiBehaviorOptions.ClientErrorMapping
            //Implement ProblemDetailsFactory
            //MVC uses Microsoft.AspNetCore.Mvc.ProblemDetailsFactory to produce all instances of ProblemDetails and ValidationProblemDetails.This includes client error responses, validation failure error responses, and the Microsoft.AspNetCore.Mvc.ControllerBase.Problem and ValidationProblem() helper methods.
            //To customize the problem details response, register a custom implementation of ProblemDetailsFactory in Startup.ConfigureServices:
            //services.AddTransient<ProblemDetailsFactory, CustomProblemDetailsFactory>();

            //services.PostConfigure<ApiBehaviorOptions>(options =>
            //{
            //    var builtInFactory = options.InvalidModelStateResponseFactory;

            //    options.InvalidModelStateResponseFactory = context =>
            //    {
            //        // Get an instance of ILogger (see below) and log accordingly.

            //        return builtInFactory(context);
            //    };
            //});

            //services.AddApiVersioning(o => o.ApiVersionReader = new HeaderApiVersionReader("api-version"));
            //services.AddApiVersioning(
            //    o =>
            //    {
            //      o.AssumeDefaultVersionWhenUnspecified = true );
            //        o.DefaultApiVersion = new ApiVersion(1);
            //    }
            //);
            //        services.AddApiVersioning(
            //o =>
            //{
            //o.AssumeDefaultVersionWhenUnspecified = true );
            //        o.DefaultApiVersion = new ApiVersion(new DateTime(2016, 7, 1));
            //    } );
            //Your versions can look however'd you like them to:
            /// api / foo ? api - version = 1.0
            /// api / foo ? api - version = 2.0 - Alpha
            /// api / foo ? api - version = 2015 - 05 - 01.3.0
            /// api / v1 / foo
            /// api / v2.0 - Alpha / foo
            /// api / v2015 - 05 - 01.3.0 / foo
            ///     services.AddApiVersioning(o => o.ApiVersionReader = new HeaderApiVersionReader("api-version"));
            //services.AddApiVersioning(options =>
            //{
            //        // reporting api versions will return the headers "api-supported-versions" and "api-deprecated-versions"
            //        options.ReportApiVersions = true;
            //});
            //services.AddApiVersioning(options =>
            //{
            //    // reporting api versions will return the headers "api-supported-versions" and "api-deprecated-versions"
            //    options.ReportApiVersions = true;

            //    // automatically applies an api version based on the name of the defining controller's namespace
            //    options.Conventions.Add(new VersionByNamespaceConvention());
            //});
            //services.AddApiVersioning(
            //  options =>
            //  {
            //            // reporting api versions will return the headers "api-supported-versions" and "api-deprecated-versions"
            //            options.ReportApiVersions = true;

            //      options.Conventions.Controller<TodoItemsController>().HasApiVersion(1, 0);

            //      options.Conventions.Controller<TodoItemsController>()
            //                         .HasApiVersion(2, 0)
            //                         .HasApiVersion(3, 0)
            //                         .Action(c => c.GetV3(default)).MapToApiVersion(3, 0)
            //                         .Action(c => c.GetV3(default, default)).MapToApiVersion(3, 0);

            //      options.Conventions.Controller<TodoItemsController>()
            //                         .HasApiVersion(1, 0)
            //                         .HasApiVersion(2, 0)
            //                         .AdvertisesApiVersion(3, 0);
            //  });

            services.AddApiVersioning(options =>
            {
                options.AssumeDefaultVersionWhenUnspecified = true;
                options.DefaultApiVersion = new ApiVersion(1, 0);
                options.ReportApiVersions = true;
                options.Conventions.Controller<V1.Controllers.TodoItemsController>().HasApiVersion(1, 0);
                //options.Conventions.Controller<V2.Controllers.TodoItemsController>().HasApiVersion(2, 0);
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                //Exception handler
                //The preceding Error action sends an RFC7807 - compliant payload to the client.

                //Exception Handling Middleware can also provide more detailed content - negotiated output in the local development environment. Use the following steps to produce a consistent payload format across development and production environments:
                //In Startup.Configure, register environment-specific Exception Handling Middleware instances:
                //In the preceding code, the middleware is registered with:

                //A route of / error - local - development in the Development environment.
                //A route of / error in environments that aren't Development.
                //Apply attribute routing to controller actions:
                app.UseExceptionHandler("/error-local-development");
                //app.UseDeveloperExceptionPage();
                //app.UseDatabaseErrorPage();
            }
            else
            {
                //In non-development environments, Exception Handling Middleware can be used to produce an error payload:
                app.UseExceptionHandler("/error");
                //app.UseHsts();
            }

            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.UseHttpsRedirection();

            // Enable middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger();

            // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.),
            // specifying the Swagger JSON endpoint.
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
                //c.SwaggerEndpoint("/swagger/v2/swagger.json", "My API V1");
                //c.RoutePrefix = string.Empty;
            });

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

            SeedDB.Initialize(app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope().ServiceProvider);
        }
    }
}
