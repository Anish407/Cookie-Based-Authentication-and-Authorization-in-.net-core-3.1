using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ConfArch.Data.Repositories;
using ConfArch.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ConfArch.Web.Controllers
{

    public class AccountController : Controller
    {
        public AccountController(IUserRepository userRepository)
        {
            UserRepository = userRepository;
        }

        public IUserRepository UserRepository { get; }

        [AllowAnonymous]
        public IActionResult Login(string returnUrl = "/")
        {
            return View(new LoginModel { ReturnUrl = returnUrl });
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            // we get the user
            var user = this.UserRepository.GetByUsernameAndPassword(model.Username, model.Password);

            if (user == null) return Unauthorized();

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("FavoriteColor", user.FavoriteColor)
            };

           // httpcontext has claims principal, when we have different authentication mechanisms we will have more than
           // one claimsIdentity, in this case we are filling in claims identity for cookie based auth
           //  we create a claims principal using the claimsIdentity and sign in using our
           // httpcontext.So our httpcontext will have claims principal with claims identity array
           //with all the different claims. We have set default auth scheme to cookie,
           //so this cookie will have different options like shud it be persistent or not
           //  we can customize based on our needs.
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(claimsIdentity);

            await HttpContext.SignInAsync(
                 CookieAuthenticationDefaults.AuthenticationScheme,
                 principal,
                 new AuthenticationProperties { IsPersistent = model.RememberLogin });

            return LocalRedirect(model.ReturnUrl);
        }

        [AllowAnonymous]
        public IActionResult LoginWithGoogle(string returnUrl = "/")
        {
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleLoginCallback"),
                Items =
                {
                    { "returnUrl", returnUrl }
                }
            };
            return Challenge(props, GoogleDefaults.AuthenticationScheme);
        }

        [AllowAnonymous]
        public async Task<IActionResult> GoogleLoginCallback()
        {
            // read google identity from the temporary cookie
            // this cookie will have google claims
            var result = await HttpContext.AuthenticateAsync(
                ExternalAuthenticationDefaults.AuthenticationScheme);

            // we read the claims and then 
            var externalClaims = result.Principal.Claims.ToList();

            //we get the google unique identifier for the user and then if the id doesnt 
            // exist we can save it(for the first time). 
           
            var subjectIdClaim = externalClaims.FirstOrDefault(
                x => x.Type == ClaimTypes.NameIdentifier);
            var subjectValue = subjectIdClaim.Value;

            //If the id exists in the DB for the user, then we get the user roles or 
            // any other detail that we need from the db 
            var user = UserRepository.GetByGoogleId(subjectValue);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("FavoriteColor", user.FavoriteColor)
            };

            // we create another claims principal from the claims and assign it to the 
            // cookie from the old cookie scheme
            var identity = new ClaimsIdentity(claims,
                CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            // delete temporary cookie used during google authentication
            await HttpContext.SignOutAsync(
                ExternalAuthenticationDefaults.AuthenticationScheme);

            // sign in using the cookie scheme, since we have implemented logout using the cookie scheme
            // we will do this for all providers since we can follow the same scheme 
            // and logout using the same scheme so that the cookie is removed safely
            // else we will have to remove each cookie that we create for each login provider.
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme, principal);

            return LocalRedirect(result.Properties.Items["returnUrl"]);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Redirect("/");
        }
    }
}