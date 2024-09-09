using IdentityApp.Models;
using IdentityApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class AccountController : Controller
    {

        private UserManager<AppUser> _userManager ;
        private RoleManager<AppRole> _roleManager;
        private SignInManager<AppUser> _signInManager;
        private IEmailSender _emailSender;


        public AccountController(
        UserManager<AppUser> userManager,
        RoleManager<AppRole> roleManager, 
        SignInManager<AppUser> signInManager,
        IEmailSender emailSender
        )

        {
            _roleManager = roleManager;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }




        public IActionResult Login()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if(user != null)
                {
                    await _signInManager.SignOutAsync();

                    if(!await _userManager.IsEmailConfirmedAsync(user))
                    {
                        ModelState.AddModelError("", "Confirm your account.");  
                        return View(model);
                    }

                    var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe,true);

                    if(result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _userManager.SetLockoutEndDateAsync(user, null);

                        return RedirectToAction("Index","Home");
                    }

                    else if(result.IsLockedOut)
                    {
                        var lockoutDate = await _userManager.GetLockoutEndDateAsync(user);
                        var timeLeft = lockoutDate.Value - DateTime.UtcNow;
                        ModelState.AddModelError("", $"Your account is locked, please try again in {timeLeft.Minutes} minutes");
                    }

                    else
                    {
                        ModelState.AddModelError("", "Incorrect Password");
                    }

                }

                    else
                    {
                        ModelState.AddModelError("", "Incorrect E-mail");
                    }

            }

            return View(model);
        }
        



        public IActionResult Create()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> Create(CreateViewModel model)
        {
            if(ModelState.IsValid)
            {
                var user = new AppUser {
                UserName= model.UserName,
                Email=model.Email,
                FullName= model.FullName};

                IdentityResult result = await _userManager.CreateAsync(user,model.Password);

                if(result.Succeeded)
                {   
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var url = Url.Action("ConfirmEmail", "Account", new{user.Id, token});

                    // email
                    await _emailSender.SendEmailAsync(user.Email, "Account Confirmation",
                    $"Please <a href='http://localhost:5233{url}'>click</a> on the link to confirm your account.");



                    TempData["message"] = "Click on the confirmation link in your email account.";
                    return RedirectToAction("Login", "Account");

                }

                foreach (IdentityError err in result.Errors)
                {
                    ModelState.AddModelError("",err.Description);
                }

                
            }

            return View(model);
            
        }


        public async Task<IActionResult> ConfirmEmail(string Id, string token)
        {
            if(Id == null || token == null)
            {   
                TempData["message"] = "Invalid token information";
                return View();
            }

            var user = await _userManager.FindByIdAsync(Id);

            if(user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                
                if(result.Succeeded)
                {
                   TempData["message"] = "Your account has been confirmed"; 
                   return RedirectToAction("Login","Account");
                }
            }

            TempData["message"] = "User not found";
            return View();

        }


        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login");
        }



        public IActionResult ForgotPassword()
        {
            return View();
        }




        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string Email)
        {   
            if(string.IsNullOrEmpty(Email))
            {
                TempData["message"] = " Please enter your e-mail address";

                return View();
            }

            var user = await _userManager.FindByEmailAsync(Email);

            if(user == null)
            {
                TempData["message"] = "Invalid e-mail address";
                return View();
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var url = Url.Action("ResetPassword", "Account", new{user.Id, token});

            await _emailSender.SendEmailAsync(Email, "Reset Password", $"<a href='http://localhost:5233{url}'>Click</a> on the link to reset your password");

            TempData["message"] = "You can reset your password with the link sent to your email address.";

            return View();
        }



        public IActionResult ResetPassword(string Id, string token)
        {
            if(Id == null || token == null)
            {
                return RedirectToAction("Login");
            }

            var model = new ResetPasswordModel {Token = token};
            return View(model);
        }




        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if(user == null)
                {
                    TempData["message"] = "There are no users matching this email address.";
                    return RedirectToAction("Login");
                }
                
                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                if(result.Succeeded)
                {
                    TempData["message"] = "Your password has been changed";
                    return RedirectToAction("Login");
                }

                foreach (IdentityError err in result.Errors)
                {
                    ModelState.AddModelError("",err.Description);
                }

            }

            return View();
        }   












 

    }
}