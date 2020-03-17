using ConfArch.Data;
using ConfArch.Data.Repositories;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ConfArch.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews(options => options.Filters.Add(new AuthorizeFilter()));

            services.AddScoped<IConferenceRepository, ConferenceRepository>();
            services.AddScoped<IProposalRepository, ProposalRepository>();
            services.AddScoped<IAttendeeRepository, AttendeeRepository>();
            services.AddScoped<IUserRepository, UserRepository>();

            services.AddDbContext<ConfArchDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"),
                    assembly => assembly.MigrationsAssembly(typeof(ConfArchDbContext).Assembly.FullName)));

            // we can add the different types of authentication 
            // for ex: cookie
            //we can give it a scheme name, by default the word cookie is used.
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme; // for reconstructing claims principaln
                //commented this code as when we use multiple login providers then this will always 
                // login from google
                //o.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;// for login use google scheme
                //o.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;// use forbidden url from this scheme
            })
             .AddCookie(o =>
             {
                 o.LoginPath = "/Account/Login";
             }).AddCookie(ExternalAuthenticationDefaults.AuthenticationScheme)
             .AddGoogle(options =>
             {
                 // we add a new cookie scheme and tell google to use this scheme when login
                 // we want google claims to be in a separate cookie 
                 // check login from google to get more details
                 // when we sign in using google this cookie will have all the details.
                 // we read this cookie and create a new claims principal that will contain all 
                 //the common claims needed by all login methods, since google will contain only its claims

                 options.SignInScheme = ExternalAuthenticationDefaults.AuthenticationScheme;
                 options.ClientId = Configuration["Google:ClientId"];
                 options.ClientSecret = Configuration["Google:Secret"];
             });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Conference}/{action=Index}/{id?}");
            });
        }
    }
}
