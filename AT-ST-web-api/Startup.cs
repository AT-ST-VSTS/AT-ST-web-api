using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
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
                    options.ClientId = settingsVisualStudio["ClientId"];
                    options.ClientSecret = settingsVisualStudio["ClientSecret"];
                    options.CallbackPath = "/auth/ExternalLoginCallback";
                    var scopes = settingsVisualStudio["Scope"].Split(' ');
                    foreach (var scope in scopes)
                    {
                        options.Scope.Add(scope);
                    }
                })
                .AddGitHub(options =>
                {
                    var settingsGitHub = _configuration.GetSection("OAuthSettings:GitHub");
                    options.ClientId = settingsGitHub["ClientId"];
                    options.ClientSecret = settingsGitHub["ClientSecret"];
                    options.CallbackPath = "/auth/ExternalLoginCallback";
                    var scopes = settingsGitHub["Scope"].Split(' ');
                    foreach (var scope in scopes)
                    {
                        options.Scope.Add(scope);
                    }
                });
                // .AddCookie(o => o.LoginPath = new PathString("/login"))
                // .AddVsoAccount(options =>
                // {
                //     var OAuthVsoSettings = _configuration.GetSection("OAuthSettings:OAuthVsoSettings");

                //     options.ClientId = OAuthVsoSettings["ClientId"];
                //     options.ClientSecret = OAuthVsoSettings["ClientSecret"];
                //     options.TokenEndpoint = OAuthVsoSettings["TokenEndpoint"];
                //     options.AuthorizationEndpoint = OAuthVsoSettings["AuthorizationEndpoint"];
                //     options.CallbackPath = OAuthVsoSettings["CallbackEndpoint"];
                //     options.Scope.Clear();
                //     var scopes = OAuthVsoSettings["Scope"].Split(' ');
                //     foreach (var scope in scopes)
                //     {
                //         options.Scope.Add(scope);
                //     }
                // });


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
