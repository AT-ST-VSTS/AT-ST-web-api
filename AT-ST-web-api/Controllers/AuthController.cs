using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ATSTWebApi.Models;
using ATSTWebApi.Models.AuthViewModels;
using ATSTWebApi.Services;

namespace ATSTWebApi.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class AuthController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;
        private readonly OAuthSettings _oauthSettings;
        
        public AuthController(
            IOptions<OAuthSettings> oauthSettings,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        // [TempData]
        // public string ErrorMessage { get; set; }

        // [HttpGet]
        // [AllowAnonymous]
        // public async Task<IActionResult> Login(string returnUrl = null)
        // {
        //     // Clear the existing external cookie to ensure a clean login process
        //     await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        //     ViewData["ReturnUrl"] = returnUrl;
        //     return View();
        // }

        // [HttpPost()] // [FromBody]
        // [HttpGet("{id}", Name = "GetTodo")]
        // [AllowAnonymous]
        // [ProducesResponseType(201)]
        // [ProducesResponseType(400)]


        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            // ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    // return RedirectToLocal(returnUrl);
                    return new JsonResult(new { result.Succeeded, returnUrl });
                }
                if (result.RequiresTwoFactor)
                {
                    // return RedirectToAction(nameof(LoginWith2fa), new { returnUrl, model.RememberMe });
                    new JsonResult(new { RequiresTwoFactor = true, returnUrl, model.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    // return RedirectToAction(nameof(Lockout));
                    new JsonResult(new { result.IsLockedOut });
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    // return View(model);
                    throw new ApplicationException("Invalid login attempt.");
                }
            }

            // If we got this far, something failed, redisplay form
            // return View(model);
            return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, bool rememberMe, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, model.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with 2fa.", user.Id);
                // return RedirectToLocal(returnUrl);
                return new JsonResult(new { result.Succeeded, returnUrl });
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                // return RedirectToAction(nameof(Lockout));
                return new JsonResult(new { result.IsLockedOut });
            }
            else
            {
                _logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                // return RedirectToLocal(returnUrl);
                return new JsonResult(new { result.Succeeded, returnUrl });
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                // return RedirectToAction(nameof(Lockout));
                return new JsonResult(new { result.IsLockedOut });
            }
            else
            {
                _logger.LogWarning("Invalid recovery code entered for user with ID {UserId}", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult LoginExternal(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(LoginExternalCallback), "auth", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }
        
    
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginExternalCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                // ErrorMessage = $"Error from external provider: {remoteError}";
                // return RedirectToAction(nameof(Login));
                return new JsonResult(new { Succeeded = false, remoteError });
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                // return RedirectToAction(nameof(Login));
                return new JsonResult(new { Succeeded = false, ExternalLoginInfo = false });
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                return new JsonResult(new { result.Succeeded, returnUrl });
                // return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                // return RedirectToAction(nameof(Lockout));
                return new JsonResult(new { result.IsLockedOut });
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["LoginProvider"] = info.LoginProvider;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return new JsonResult(new { Register = true, info.LoginProvider, Email = email, returnUrl });
                // return View("ExternalLogin", new ExternalLoginViewModel { Email = email });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginExternalConfirmation(ExternalLoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        // return RedirectToLocal(returnUrl);
                        return new JsonResult(new { result.Succeeded, returnUrl });
                    }
                }
                AddErrors(result);
            }

            ViewData["ReturnUrl"] = returnUrl;
            // return View(nameof(ExternalLogin), model);
            return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState, ReturnUrl = returnUrl });
        }
        
        [HttpPost]
        [AllowAnonymous]
        // [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
                    await _emailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);

                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("User created a new account with password.");
                    // return RedirectToLocal(returnUrl);
                    return new JsonResult(new { result.Succeeded, returnUrl });
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
        }

        [HttpPost]
        // [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            // return RedirectToAction(nameof(HomeController.Index), "Home");
            return new JsonResult(new { Succeeded = true });
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                // return RedirectToAction(nameof(HomeController.Index), "Home");
                return new JsonResult(new { Succeeded = false });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            // return View(result.Succeeded ? "ConfirmEmail" : "Error");
            return new JsonResult(new { result.Succeeded });
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    // return RedirectToAction(nameof(ForgotPasswordConfirmation));
                    return new JsonResult(new { Succeeded = false });
                }

                // For more information on how to enable account confirmation and password reset please
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);
                await _emailSender.SendEmailAsync(model.Email, "Reset Password",
                   $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
                // return RedirectToAction(nameof(ForgotPasswordConfirmation));
                return new JsonResult(new { Succeeded = true });
            }

            // If we got this far, something failed, redisplay form
            // return View(model);
            return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
        }

        // [HttpGet]
        // [AllowAnonymous]
        // public IActionResult ResetPassword(string code = null)
        // {
        //     if (code == null)
        //     {
        //         throw new ApplicationException("A code must be supplied for password reset.");
        //     }
        //     var model = new ResetPasswordViewModel { Code = code };
        //     return View(model);
        // }

        [HttpPost]
        [AllowAnonymous]
        // [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                // return View(model);
                return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                // return RedirectToAction(nameof(ResetPasswordConfirmation));
                return new JsonResult(new { Succeeded = false });
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                // return RedirectToAction(nameof(ResetPasswordConfirmation));
                return new JsonResult(new { result.Succeeded });
            }
            AddErrors(result);
            // return View();
            return new JsonResult(new { ModelState.IsValid, ModelState.ValidationState });
        }

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        // private IActionResult RedirectToLocal(string returnUrl)
        // {
        //     if (Url.IsLocalUrl(returnUrl))
        //     {
        //         return Redirect(returnUrl);
        //     }
        //     else
        //     {
        //         return RedirectToAction(nameof(HomeController.Index), "Home");
        //     }
        // }

        #endregion
    }
}
