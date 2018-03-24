using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using AT_ST_web_api.Data;
using AT_ST_web_api.Models;
using AT_ST_web_api.Services;
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

namespace AT_ST_web_api
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
                options.UseSqlite(_configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>(config =>
            {
                config.SignIn.RequireConfirmedEmail = true;
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
                })                
                .AddVisualStudio(options =>
                {
                    var settingsVisualStudio = _configuration.GetSection("OAuthSettings:VisualStudio");
                    options.ClientId = settingsVisualStudio["ClientId"];
                    options.ClientSecret = settingsVisualStudio["ClientSecret"];
                    options.CallbackPath = "/auth/oauth-callback-VisualStudio";
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
                    options.CallbackPath = "/auth/oauth-callback-GitHub";
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
