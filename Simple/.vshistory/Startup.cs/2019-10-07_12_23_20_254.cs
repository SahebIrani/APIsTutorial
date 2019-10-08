using System.IdentityModel.Tokens.Jwt;
using System.Text;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

using Simple.Data;
using Simple.Models;
using Simple.Services;

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

            //services.AddDefaultIdentity<IdentityUser>()
            //    .AddEntityFrameworkStores<ApplicationDbContext>();

            //services.AddIdentity<ApplicationUser, IdentityRole>()
            //    .AddEntityFrameworkStores<ApplicationDbContext>()
            //    .AddDefaultTokenProviders();



            //string domain = $"https://{Configuration["Auth0:Domain"]}/";
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    //options.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
            //    //options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            //    //options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
            //    //options.DefaultSignOutScheme = JwtBearerDefaults.AuthenticationScheme;
            //    //options.RequireAuthenticatedSignIn = true;
            //})
            ////.AddCookie(cfg => cfg.SlidingExpiration = true)
            //.AddJwtBearer(options =>
            //{
            //    //options.Authority =
            //    //    string.Format("https://login.microsoftonline.com/tfp/{0}/{1}/v2.0/",
            //    //    Configuration["Authentication:AzureAd:Tenant"],
            //    //    Configuration["Authentication:AzureAd:Policy"]);
            //    //options.Audience = Configuration["Authentication:AzureAd:ClientId"];
            //    //options.Events = new JwtBearerEvents
            //    //{
            //    //    OnAuthenticationFailed = AuthenticationFailed
            //    //};

            //    //options.SecurityTokenValidators.Clear();
            //    //options.SecurityTokenValidators.Add((ISecurityTokenValidator)new GoogleTokenValidator());

            //    //options.UseGoogle(
            //    //    //clientId: "<client-id-from-Google-API-console>",
            //    //    clientId: (string)"699546342820-fhle0afn3g1gi19t9k1b27s7vhcb321a.apps.googleusercontent.com",
            //    //    hostedDomain: (string)"<optional-hosted-domain>"
            //    //);

            //    options.SaveToken = true;
            //    options.RequireHttpsMetadata = false;
            //    options.TokenValidationParameters = new TokenValidationParameters()
            //    {
            //        //ValidateIssuerSigningKey = true,
            //        //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your secret goes here")),

            //        //ValidateIssuer = true,
            //        //ValidIssuer = "The name of the issuer",

            //        //ValidateAudience = true,
            //        //ValidAudience = "The name of the audience",

            //        //ValidateLifetime = true, //validate the expiration and not before values in the token

            //        //ClockSkew = TimeSpan.FromMinutes(5) //5 minute tolerance for the expiration date


            //        //ValidateLifetime = true,
            //        //ValidateIssuerSigningKey = true,
            //        //ValidateIssuer = true,
            //        //ValidateAudience = true,
            //        ////ValidateActor = true,
            //        //ValidateTokenReplay = true,
            //        //RequireSignedTokens = true,
            //        //RequireExpirationTime = true,
            //        //ClockSkew = TimeSpan.Zero,
            //        ValidIssuer = "SinjulMSBH",
            //        ValidAudience = "SinjulMSBH",
            //        //TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
            //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisKeyIs32CharactersLong1234567")),

            //        //ValidateAudience = false,
            //        //ValidateIssuer = false,
            //        //ValidateIssuerSigningKey = false,
            //        //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("the secret that needs to be at least 16 characeters long for HmacSha256")),
            //        //ValidateLifetime = false, //validate the expiration and not before values in the token
            //        //ClockSkew = TimeSpan.FromMinutes(5.0), //5 minute tolerance for the expiration date
            //        //ValidateActor = false,
            //        //ValidateTokenReplay = false

            //        //ValidateLifetime = true,
            //        //ValidateIssuerSigningKey = true,
            //        //ValidateIssuer = true,
            //        //ValidateAudience = true,
            //        //RequireSignedTokens = true,
            //        //RequireExpirationTime = true,
            //        //ClockSkew = TimeSpan.Zero,
            //        //RequireExpirationTime = false,
            //        //ValidAudience = "SinjulMSBH",
            //        //ValidIssuer = "SinjulMSBH",
            //        //TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
            //        //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SinjulMSBHJack_4")),
            //        //TokenDecryptionKey = new X509SecurityKey(new X509Certificate2("key_private.pfx", "idsrv3test")),
            //        //TokenDecryptionKey = new X509SecurityKey(new X509Certificate2(Encoding.UTF8.GetBytes("SinjulMSBHJack_4"), "SinjulMSBHJack_4")),
            //        //ValidIssuer = Configuration["Jwt:Issuer"],
            //        //ValidAudience = Configuration["Jwt:Audience"],
            //        //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))

            //        // When receiving a token, check that we've signed it.
            //        //ValidateIssuerSigningKey = true,

            //        // When receiving a token, check that it is still valid.
            //        //ValidateLifetime = true,

            //        // This defines the maximum allowable clock skew - i.e. provides a tolerance on the token expiry time
            //        // when validating the lifetime. As we're creating the tokens locally and validating them on the same

            //        // machines which should have synchronised time, this can be set to zero. and default value will be 5minutes
            //        //ClockSkew = TimeSpan.FromMinutes(0)
            //    };
            //    options.Validate();

            //    //options.Authority = domain;
            //    //options.Audience = Configuration["Auth0:Audience"];
            //    //options.Authority = "https://offishopp.auth0.com/";
            //    //options.Audience = "https://localhost:5001";

            //    //options.Events.OnMessageReceived = context =>
            //    //{
            //    //    string unencryptedToken = context.Token;
            //    //    string encryptedToken = /*Decrypt(unencryptedToken)*/"SinjulMSBH_encryptedToken";
            //    //    context.Token = encryptedToken;

            //    //    return Task.CompletedTask;
            //    //};

            //    options.Events = new JwtBearerEvents
            //    {
            //        OnAuthenticationFailed = async context =>
            //        {
            //            ((ILogger)context.HttpContext.RequestServices
            //                    .GetRequiredService<ILoggerFactory>()
            //                      .CreateLogger(nameof(JwtBearerEvents)))
            //                        .LogError((string)"SinjulMSBH / Access denied! Please login with an account which has enough permissions first .. !!!!", context.Exception);

            //            if (context.Exception != null)
            //            {
            //                context.HttpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            //                await context.HttpContext.Response.WriteAsync((string)"SinjulMSBH / Access denied! Please login with an account which has enough permissions first .. !!!!");
            //            }
            //        }
            //    };
            //});

            //services.AddCors(options =>
            //{
            //    options.AddPolicy("CorsPolicy",
            //        builder => builder.AllowAnyOrigin()
            //          .AllowAnyMethod()
            //          .AllowAnyHeader()
            //          .AllowCredentials()
            //    .Build());
            //});



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
            }).AddCookie("cookie").AddJwtBearer("jwt", options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(secret),
                    TokenDecryptionKey = new SymmetricSecurityKey(decryptionKey),
                    ValidIssuer = token.Issuer,
                    ValidAudience = token.Audience,
                    ValidateIssuer = false,
                    ValidateAudience = false
                };

                //options.Events.OnTokenValidated = async ctx =>
                //{
                //    string oid = ctx.Principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");

                //    //Get EF context
                //    var db = ctx.HttpContext.RequestServices.GetRequiredService<AuthorizationDbContext>();

                //    //Check is user a super admin
                //    bool isSuperAdmin = await db.SuperAdmins.AnyAsync(a => a.ObjectId == oid);
                //    if (isSuperAdmin)
                //    {
                //        //Add claim if they are
                //        var claims = new List<Claim>
                //        {
                //            new Claim(ClaimTypes.Role, "superadmin")
                //        };
                //                        var appIdentity = new ClaimsIdentity(claims);

                //                        ctx.Principal.AddIdentity(appIdentity);
                //        }
                //    }
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






            services.AddControllers()
                .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true)
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
