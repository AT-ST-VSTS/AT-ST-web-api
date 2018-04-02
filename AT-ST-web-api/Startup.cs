using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using ATSTWebApi.Data;
using ATSTWebApi.Models;
using ATSTWebApi.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Swashbuckle.AspNetCore.Swagger;

namespace ATSTWebApi
{
    public class Startup
    {

        private readonly IHostingEnvironment _hostingEnvironment;

        private readonly IConfiguration _configuration;

        public Startup(IHostingEnvironment env, IConfiguration config)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            _configuration = builder.Build();

            _hostingEnvironment = env;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Register Development settings
            if (_hostingEnvironment.IsDevelopment())
            {
            }

            // Add functionality to inject IOptions<T>
            services.AddOptions();

            services.Configure<OAuthSettings>(_configuration.GetSection("OAuthSettings"));

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(_configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, ApplicationRole>(config =>
            {
                // Lockout settings
                config.Lockout.AllowedForNewUsers = true;
                config.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                config.Lockout.MaxFailedAccessAttempts = 5; 
                // Password settings
                config.Password.RequireDigit = true;
                config.Password.RequiredLength = 8;
                config.Password.RequiredUniqueChars = 2;
                config.Password.RequireLowercase = true;
                config.Password.RequireNonAlphanumeric = true;
                config.Password.RequireUppercase = true;
                // Signin settings
                config.SignIn.RequireConfirmedEmail = false;
                config.SignIn.RequireConfirmedPhoneNumber = false;
                // User settings
                config.User.RequireUniqueEmail = true;
            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.AddSingleton<IEmailSender, EmailSender>();

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = "vso";
                })
                // https://www.blinkingcaret.com/2017/09/06/secure-web-api-in-asp-net-core/
                // {
                //     options.DefaultAuthenticateScheme = "JwtBearer";
                //     options.DefaultChallengeScheme = "JwtBearer"; 
                // })
                // .AddJwtBearer("JwtBearer", jwtBearerOptions =>
                // {                        
                //     jwtBearerOptions.TokenValidationParameters = new TokenValidationParameters
                //     {                            
                //         ValidateIssuerSigningKey = true,
                //         IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your secret goes here")),

                //         ValidateIssuer = true,
                //         ValidIssuer = "The name of the issuer",

                //         ValidateAudience = true,
                //         ValidAudience = "The name of the audience",

                //         ValidateLifetime = true, //validate the expiration and not before values in the token

                //         ClockSkew = TimeSpan.FromMinutes(5) //5 minute tolerance for the expiration date
                //     };
                // })
                .AddCookie(options =>
                {
                    // options.AccessDeniedPath = "/error/Access";
                    options.LoginPath = "/auth/LogIn";
                    options.LogoutPath = "/auth/LogOff";
                    options.AccessDeniedPath = "/auth/AccessDenied";
                    options.Cookie.Name = "atst_cookie";
                    // options.Cookie.HttpOnly = true; 
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(60); 
                    // ReturnUrlParameter requires `using Microsoft.AspNetCore.Authentication.Cookies;`
                    // options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
                    // options.SlidingExpiration = true;
                })                
                .AddVisualStudio(options =>
                {
                    var settingsVisualStudio = _configuration.GetSection("OAuthSettings:VisualStudio");
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                    options.ClaimsIssuer = "VisualStudio";
                    options.ClientId = settingsVisualStudio["ClientId"];
                    options.ClientSecret = settingsVisualStudio["ClientSecret"];
                    options.CallbackPath = "/auth/signin-visualstudio";
                    var scopes = settingsVisualStudio["Scope"].Split(' ');
                    foreach (var scope in scopes)
                    {
                        options.Scope.Add(scope);
                    }

                    options.Events = new Microsoft.AspNetCore.Authentication.OAuth.OAuthEvents
                    {
                        OnCreatingTicket = async (context) =>
                        {
                            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                            request.Headers.Add("x-li-format", "json");

                            var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                            response.EnsureSuccessStatusCode();
                            var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                            var data = user.SelectToken("data")[0];

                            var id = (string)data["id"];
                            if (!string.IsNullOrEmpty(id))
                            {
                                context.Identity.AddClaim(new Claim("id", id, ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer));
                            }

                            var DisplayName = (string)data["DisplayName"];
                            if (!string.IsNullOrEmpty(DisplayName))
                            {
                                context.Identity.AddClaim(new Claim("DisplayName", DisplayName, ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer));
                            }

                            var publicAlias = (string)data["publicAlias"];
                            if (!string.IsNullOrEmpty(publicAlias))
                            {
                                context.Identity.AddClaim(new Claim("publicAlias", publicAlias, ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer));
                            }

                            var emailAddress = (string)data["emailAddress"];
                            if (!string.IsNullOrEmpty(emailAddress))
                            {
                                context.Identity.AddClaim(new Claim("emailAddress", emailAddress, ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer));
                            }

                            // var coreRevision = (int)data["coreRevision"];
                            // context.Identity.AddClaim(new Claim("coreRevision", coreRevision.ToString(), ClaimValueTypes.Integer,
                            //     context.Options.ClaimsIssuer));

                            // var timestamp = (string)data["timestamp"];
                            // if (!string.IsNullOrEmpty(timestamp))
                            // {
                            //     context.Identity.AddClaim(new Claim("timestamp", timestamp, ClaimValueTypes.String,
                            //         context.Options.ClaimsIssuer));
                            // }

                            // var révision = (string)data["révision"];
                            //context.Identity.AddClaim(new Claim("révision", révision, ClaimValueTypes.Integer,
                            //    context.Options.ClaimsIssuer));

                        }
                     };
                })
                .AddGitHub(options =>
                {
                    var settingsGitHub = _configuration.GetSection("OAuthSettings:GitHub");
                    options.ClientId = settingsGitHub["ClientId"];
                    options.ClientSecret = settingsGitHub["ClientSecret"];
                    options.CallbackPath = "/auth/signin-github";
                    var scopes = settingsGitHub["Scope"].Split(' ');
                    foreach (var scope in scopes)
                    {
                        options.Scope.Add(scope);
                    }
                });


            // Register the Swagger generator, defining one or more Swagger documents
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new Info
                {
                    Version = "v1",
                    Title = "ToDo API",
                    Description = "A simple example ASP.NET Core Web API",
                    TermsOfService = "None",
                    Contact = new Contact { Name = "Shayne Boyer", Email = "", Url = "https://twitter.com/spboyer" },
                    License = new License { Name = "Use under LICX", Url = "https://example.com/license" }
                });

                // Set the comments path for the Swagger JSON and UI.
                var basePath = AppContext.BaseDirectory;
                var xmlPath = Path.Combine(basePath, "AT-ST-web-api.xml"); 
                c.IncludeXmlComments(xmlPath);
            });

            // Use MVC middleware
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if(env.IsProduction())
            {
                app.UseExceptionHandler("/Error");
            }
            else
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseAuthentication();

            // Use swagger middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger();

            // Use swagger middleware to serve swagger-ui (HTML, JS, CSS, etc.), specifying the Swagger JSON endpoint.
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
            });

            // Use MVC middleware
            app.UseMvc();
        }
    }
}
