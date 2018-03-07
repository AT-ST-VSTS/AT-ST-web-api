using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;
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
        public Startup(IHostingEnvironment env, IConfiguration config)
        {
            this.Configuration = config;

            HostingEnvironment = env;
        }

        public IHostingEnvironment HostingEnvironment { get; private set; }

        public IConfiguration Configuration { get; private set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // if (HostingEnvironment.IsDevelopment())
            // {
            //     services.Configure<MvcOptions>(options =>
            //     {
            //         options.Filters.Add(new RequireHttpsAttribute());
            //     });
            // }

            services.AddMvc();

            // services.Configure<IConfigurationSection>(Configuration.GetSection("oauth:vso"));
            // services.Configure<IConfiguration>(this.Configuration);
            services.AddSingleton<IConfiguration>(Configuration);

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

            // services.ConfigureApplicationCookie(options =>
            // {
            //     // Cookie settings
            //     options.Cookie.HttpOnly = true;
            //     options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            //     options.LoginPath = "/Account/Login"; // If the LoginPath is not set here, ASP.NET Core will default to /Account/Login
            //     options.LogoutPath = "/Account/Logout"; // If the LogoutPath is not set here, ASP.NET Core will default to /Account/Logout
            //     options.AccessDeniedPath = "/Account/AccessDenied"; // If the AccessDeniedPath is not set here, ASP.NET Core will default to /Account/AccessDenied
            //     options.SlidingExpiration = true;
            // });

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = "VSTS";
            })
            .AddCookie(options => options.LoginPath = new PathString("/account/login"))
            .AddOAuth("VSTS", options =>
            {
                options.ClientId = this.Configuration["oauth:vso:ClientId"];
                options.ClientSecret = this.Configuration["oauth:vso:ClientSecret"];
                options.CallbackPath = new PathString("/oauth-callback");

                options.AuthorizationEndpoint = "https://app.vssps.visualstudio.com/oauth2/authorize?";
                options.TokenEndpoint = "https://app.vssps.visualstudio.com/oauth2/token?mkt=en-US";
                // options.UserInformationEndpoint = "https://api.github.com/user";

                options.Scope.Add("vso.dashboards");
                options.Scope.Add("vso.entitlements");
                options.Scope.Add("vso.identity");
                options.Scope.Add("vso.project");
                options.Scope.Add("vso.work");
                options.Scope.Add("vso.workitemsearch");

                options.ClaimActions.MapJsonKey("access_token", "access_token");
                options.ClaimActions.MapJsonKey("token_type", "token_type");
                options.ClaimActions.MapJsonKey("expires_in", "expires_in");
                options.ClaimActions.MapJsonKey("refresh_token", "refresh_token");

                // options.Events = new OAuthEvents
                // {
                //     OnCreatingTicket = async context =>
                //     {
                //         // var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                //         // request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                //         // request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

                //         // var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                //         // response.EnsureSuccessStatusCode();

                //         // var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                //         // context.RunClaimActions(user);

                //         var user = JObject.Parse(await context..ReadAsStringAsync());

                //         context.RunClaimActions(user);
                //     }
                // };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment() || env.IsStaging())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            if (env.IsDevelopment())
            {
                // var options = new RewriteOptions().AddRedirectToHttps(StatusCodes.Status301MovedPermanently, 63423);
                // app.UseRewriter(options);
            }

            // Enable middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger();

            // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.), specifying the Swagger JSON endpoint.
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
            });

            app.UseMvc();

            //Adds the authentication middleware to the pipeline
            app.UseAuthentication();
        }
    }
}
