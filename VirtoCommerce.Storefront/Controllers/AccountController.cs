using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using VirtoCommerce.Storefront.AutoRestClients.PlatformModuleApi;
using VirtoCommerce.Storefront.Domain;
using VirtoCommerce.Storefront.Domain.Common;
using VirtoCommerce.Storefront.Domain.Security;
using VirtoCommerce.Storefront.Domain.Security.Notifications;
using VirtoCommerce.Storefront.Extensions;
using VirtoCommerce.Storefront.Infrastructure;
using VirtoCommerce.Storefront.Infrastructure.Senders;
using VirtoCommerce.Storefront.Model;
using VirtoCommerce.Storefront.Model.Common;
using VirtoCommerce.Storefront.Model.Common.Events;
using VirtoCommerce.Storefront.Model.Security;
using VirtoCommerce.Storefront.Model.Security.Events;
using VirtoCommerce.Storefront.Model.Security.Specifications;

namespace VirtoCommerce.Storefront.Controllers
{
    [StorefrontRoute("account")]
    public class AccountController : StorefrontControllerBase
    {
        private readonly SignInManager<User> _signInManager;
        private readonly IEventPublisher _publisher;
        private readonly StorefrontOptions _options;
        private readonly INotifications _platformNotificationApi;
        private readonly IAuthorizationService _authorizationService;
        private readonly Func<ISmsSender> _smsSenderFactory;

        private readonly string[] _firstNameClaims = { ClaimTypes.GivenName, "urn:github:name", ClaimTypes.Name };

        public AccountController(
            IWorkContextAccessor workContextAccessor,
            IStorefrontUrlBuilder urlBuilder,
            SignInManager<User> signInManager,
            IEventPublisher publisher,
            INotifications platformNotificationApi,
            IAuthorizationService authorizationService,
            IOptions<StorefrontOptions> options,
            Func<ISmsSender> smsSenderFactory)
            : base(workContextAccessor, urlBuilder)
        {
            _signInManager = signInManager;
            _publisher = publisher;
            _options = options.Value;
            _platformNotificationApi = platformNotificationApi;
            _authorizationService = authorizationService;
            _smsSenderFactory = smsSenderFactory;
        }

        //GET: /account
        [HttpGet]
        [Authorize(OnlyRegisteredUserAuthorizationRequirement.PolicyName)]
        public ActionResult GetAccount()
        {
            //Customer should be already populated in WorkContext middle-ware
            return View("customers/account", WorkContext);
        }

        [HttpGet("order/{number}")]
        [Authorize(OnlyRegisteredUserAuthorizationRequirement.PolicyName)]
        public ActionResult GetOrderDetails(string number)
        {
            var order = WorkContext.CurrentUser?.Orders.FirstOrDefault(x => x.Number.EqualsInvariant(number));
            if (order != null)
            {
                WorkContext.CurrentOrder = order;
            }

            return View("customers/order", WorkContext);
        }

        [HttpGet("addresses")]
        [Authorize(OnlyRegisteredUserAuthorizationRequirement.PolicyName)]
        public ActionResult GetAddresses()
        {
            return View("customers/addresses", WorkContext);
        }

        [HttpGet("register")]
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View("customers/register", WorkContext);
        }

        [HttpPost("register")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register([FromForm] UserRegistration registration)
        {
            TryValidateModel(registration);

            if (ModelState.IsValid)
            {
                //Register user
                var user = registration.ToUser();
                user.Contact = registration.ToContact();
                user.StoreId = WorkContext.CurrentStore.Id;

                var result = await _signInManager.UserManager.CreateAsync(user, registration.Password);
                if (result.Succeeded)
                {
                    user = await _signInManager.UserManager.FindByNameAsync(user.UserName);
                    await _publisher.Publish(new UserRegisteredEvent(WorkContext, user, registration));

                    await _signInManager.SignInAsync(user, isPersistent: true);
                    await _publisher.Publish(new UserLoginEvent(WorkContext, user));

                    if (_options.SendAccountConfirmation)
                    {
                        var token = await _signInManager.UserManager.GenerateEmailConfirmationTokenAsync(user);
                        var callbackUrl = Url.Action("ConfirmEmail", "Account", new { UserId = user.Id, Token = token }, protocol: Request.Scheme);
                        var emailConfirmationNotification = new EmailConfirmationNotification(WorkContext.CurrentStore.Id, WorkContext.CurrentLanguage)
                        {
                            Url = callbackUrl,
                            Sender = WorkContext.CurrentStore.Email,
                            Recipient = GetUserEmail(user)
                        };
                        await _platformNotificationApi.SendNotificationAsync(emailConfirmationNotification.ToNotificationDto());
                    }

                    return StoreFrontRedirect("~/account");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("form", error.Description);
                    }
                }
            }

            WorkContext.Form = registration;
            return View("customers/register", WorkContext);
        }

        [HttpGet("confirminvitation")]
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmInvitation(string organizationId, string email, string token)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                WorkContext.ErrorMessage = "Error in URL format";
                return View("error", WorkContext);
            }

            var user = await _signInManager.UserManager.FindByEmailAsync(email);
            if (user == null)
            {
                WorkContext.ErrorMessage = "User was not found.";
                return View("error", WorkContext);
            }

            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                WorkContext.ErrorMessage = "Sorry, this invitation can be used only once.";
                return View("error", WorkContext);
            }

            var isValidToken = await _signInManager.UserManager.VerifyUserTokenAsync(user, _signInManager.UserManager.Options.Tokens.PasswordResetTokenProvider, UserManager<User>.ResetPasswordTokenPurpose, token);
            if (!isValidToken)
            {
                WorkContext.ErrorMessage = "Invitation token is invalid or expired";
                return View("error", WorkContext);
            }

            WorkContext.Form = new UserRegistrationByInvitation
            {
                Email = email,
                OrganizationId = organizationId,
                Token = token
            };

            return View("customers/confirm_invitation", WorkContext);
        }

        [HttpPost("confirminvitation")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ConfirmInvitation([FromForm] UserRegistrationByInvitation register)
        {
            var result = IdentityResult.Success;
            TryValidateModel(register);

            if (ModelState.IsValid)
            {
                var user = await _signInManager.UserManager.FindByEmailAsync(register.Email);
                if (user != null)
                {
                    result = await _signInManager.UserManager.ResetPasswordAsync(user, register.Token, register.Password);
                    if (result.Succeeded)
                    {
                        user.UserName = register.UserName;
                        user.Contact = register.ToContact();
                        user.Contact.OrganizationId = register.OrganizationId;

                        result = await _signInManager.UserManager.UpdateAsync(user);
                        if (result.Succeeded)
                        {
                            await _publisher.Publish(new UserRegisteredEvent(WorkContext, user, register));
                            await _signInManager.SignInAsync(user, isPersistent: true);
                            await _publisher.Publish(new UserLoginEvent(WorkContext, user));
                        }

                        return StoreFrontRedirect("~/account");
                    }
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            WorkContext.Form = register;
            return View("customers/confirm_invitation", WorkContext);
        }

        [HttpGet("confirmemail")]
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string token)
        {
            var result = await _signInManager.UserManager.ConfirmEmailAsync(WorkContext.CurrentUser, token);
            var viewName = result.Succeeded ? "confirmation-done" : "error";
            return View(viewName);
        }

        [HttpGet("impersonate/{userId}")]
        public async Task<IActionResult> ImpersonateUser(string userId)
        {
            if (User.Identity.Name == SecurityConstants.AnonymousUsername)
            {
                return StoreFrontRedirect($"~/account/login?ReturnUrl={Request.Path}");
            }
            var authorizationResult = await _authorizationService.AuthorizeAsync(User, null, CanImpersonateAuthorizationRequirement.PolicyName);
            if (!authorizationResult.Succeeded)
            {
                return Forbid();
            }
            var impersonateUser = await _signInManager.UserManager.FindByIdAsync(userId);
            if (impersonateUser != null)
            {
                impersonateUser.OperatorUserId = WorkContext.CurrentUser.Id;
                impersonateUser.OperatorUserName = WorkContext.CurrentUser.UserName;

                // sign out the current user
                await _signInManager.SignOutAsync();

                await _signInManager.SignInAsync(impersonateUser, isPersistent: false);
            }
            return StoreFrontRedirect("~/");
        }

        [HttpGet("login")]
        [AllowAnonymous]
        public ActionResult Login()
        {
            return View("customers/login");
        }

        [HttpPost("login")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login([FromForm] Login login, string returnUrl)
        {
            TryValidateModel(login);

            if (!ModelState.IsValid)
            {
                return View("customers/login", WorkContext);
            }
            login.Username = login.Username?.Trim();

            var loginResult = await _signInManager.PasswordSignInAsync(login.Username, login.Password, login.RememberMe, lockoutOnFailure: true);

            if (loginResult.Succeeded)
            {
                var user = await _signInManager.UserManager.FindByNameAsync(login.Username);

                if (new CanUserLoginToStoreSpecification(user).IsSatisfiedBy(WorkContext.CurrentStore))
                {
                    await _publisher.Publish(new UserLoginEvent(WorkContext, user));
                    return StoreFrontRedirect(returnUrl);
                }
                else
                {
                    ModelState.AddModelError("form", "User cannot login to current store.");
                }
            }

            if (loginResult.RequiresTwoFactor)
            {
                var user = await _signInManager.UserManager.FindByNameAsync(login.Username);

                // Generate the token and send it

                // TODO: Support configurable providers ("Phone/Email")
                // https://github.com/aspnet/Docs/blob/aac9bf5e4aaa4f593648ddb7b92ff0e52f2f6a47/aspnetcore/security/authentication/2fa/sample/Web2FA/Controllers/AccountController.cs#L380
                // Now we are using only Phone provider
                var selectedProvider = "Phone";

                var userManager = _signInManager.UserManager;
                var code = await userManager.GenerateTwoFactorTokenAsync(user, selectedProvider);
                if (string.IsNullOrWhiteSpace(code))
                {
                    WorkContext.ErrorMessage = $"Generated two factor authentication token is empty";
                    return View("error", WorkContext);
                }

                var veryfyCodeViewModel = new VerifyCodeViewModel() { Provider = selectedProvider, ReturnUrl = returnUrl, RememberMe = login.RememberMe, Username = login.Username };
                var message = "Your security code is: " + code;
                if (veryfyCodeViewModel.Provider == "Phone")
                {
                    await _smsSenderFactory().SendSmsAsync(await userManager.GetPhoneNumberAsync(user), message);
                }
                //else if (veryfyCodeViewModel.Provider == "Email")
                //{
                //    await _emailSender.SendEmailAsync(await userManager.GetEmailAsync(user), "Security Code", message);
                //}

                WorkContext.Form = veryfyCodeViewModel;
                return View("verify-code", WorkContext);
            }

            if (loginResult.IsLockedOut)
            {
                return View("lockedout", WorkContext);
            }

            if (loginResult is CustomSignInResult signInResult && signInResult.IsRejected)
            {
                ModelState.AddModelError("form", "Administrator suspended this account");
            }

            ModelState.AddModelError("form", "Login attempt failed.");
            WorkContext.Form = login;

            return View("customers/login", WorkContext);
        }

        [HttpPost("verifycode")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            TryValidateModel(model);
            if (!ModelState.IsValid)
            {
                return View("verify-code", WorkContext);
            }

            // The following code protects for brute force attacks against the two factor codes.
            // If a user enters incorrect codes for a specified amount of time then the user account
            // will be locked out for a specified amount of time.
            var result = await _signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe ?? false, model.RememberBrowser ?? false);
            if (result.Succeeded)
            {
                var user = await _signInManager.UserManager.FindByNameAsync(model.Username);
                await _publisher.Publish(new UserLoginEvent(WorkContext, user));
                return StoreFrontRedirect(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("lockedout", WorkContext);
            }

            ModelState.AddModelError("form", "Invalid code.");
            WorkContext.Form = model;
            return View("verify-code", WorkContext);
        }

        [HttpGet("logout")]
        [AllowAnonymous]
        public async Task<ActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return StoreFrontRedirect("~/");
        }

        [HttpGet("externallogin")]
        [AllowAnonymous]
        public ActionResult ExternalLogin(string authType, string returnUrl)
        {
            if (string.IsNullOrEmpty(authType))
            {
                return new BadRequestResult();
            }

            var properties = _signInManager.ConfigureExternalAuthenticationProperties(authType, Url.Action("ExternalLoginCallback", "Account", new { returnUrl }));
            return Challenge(properties, authType);
        }

        [HttpGet("externallogincallback")]
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await _signInManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return View("customers/login", WorkContext);
            }

            User user;

            // Sign in the user with this external login provider if the user already has a login.
            var externalLoginResult = await _signInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (!externalLoginResult.Succeeded)
            {
                //TODO: Locked out not work. Need to add some API methods to support lockout data.
                if (externalLoginResult.IsLockedOut)
                {
                    return View("lockedout", WorkContext);
                }

                IdentityResult identityResult;

                var currentUser = WorkContext.CurrentUser;
                if (currentUser.IsRegisteredUser)
                {
                    identityResult = await _signInManager.UserManager.AddLoginAsync(currentUser, loginInfo);
                }
                else
                {
                    user = new User
                    {
                        Email = loginInfo.Principal.FindFirstValue(ClaimTypes.Email),
                        UserName = $"{loginInfo.LoginProvider}--{loginInfo.ProviderKey}",
                        StoreId = WorkContext.CurrentStore.Id,
                    };

                    user.ExternalLogins.Add(new ExternalUserLoginInfo { ProviderKey = loginInfo.ProviderKey, LoginProvider = loginInfo.LoginProvider });

                    var userRegistration = new UserRegistration
                    {
                        FirstName = loginInfo.Principal.FindFirstValue(_firstNameClaims, "unknown"),
                        LastName = loginInfo.Principal.FindFirstValue(ClaimTypes.Surname),
                        UserName = user.UserName,
                        Email = user.Email
                    };
                    user.Contact = userRegistration.ToContact();

                    identityResult = await _signInManager.UserManager.CreateAsync(user);
                    if (identityResult.Succeeded)
                    {
                        await _publisher.Publish(new UserRegisteredEvent(WorkContext, user, userRegistration));
                    }
                }

                if (!identityResult.Succeeded)
                {
                    foreach (var error in identityResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    return View("customers/login", WorkContext);
                }
            }

            user = await _signInManager.UserManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);

            if (!externalLoginResult.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
            }
            await _publisher.Publish(new UserLoginEvent(WorkContext, user));

            return StoreFrontRedirect(returnUrl);
        }

        [HttpGet("forgotpassword")]
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View("customers/forgot_password", WorkContext);
        }

        [HttpPost("forgotpassword")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPassword formModel)
        {
            var user = await _signInManager.UserManager.FindByEmailAsync(formModel.Email);
            if (user != null)
            {
                if (_options.UseSmsForPasswordReset)
                {
                    var phoneNumber = await _signInManager.UserManager.GetPhoneNumberAsync(user);
                    if (string.IsNullOrEmpty(phoneNumber))
                    {
                        ModelState.AddModelError("form", "Phone is not assigned to the user");
                    }
                    else
                    {
                        var token = await _signInManager.UserManager.GenerateUserTokenAsync(user, TokenOptions.DefaultPhoneProvider, "ResetPassword");

                        var resetPasswordSmsNotification = new ResetPasswordSmsNotification(WorkContext.CurrentStore.Id, WorkContext.CurrentLanguage)
                        {
                            Token = token,
                            Recipient = phoneNumber,
                        };

                        var sendingResult = await _platformNotificationApi.SendNotificationAsync(resetPasswordSmsNotification.ToNotificationDto());
                        if (sendingResult.IsSuccess == true)
                        {
                            WorkContext.CurrentUser = user;
                            return View($"customers/forgot_password_code", WorkContext);
                        }
                        else
                        {
                            ModelState.AddModelError("form", sendingResult.ErrorMessage);
                        }
                    }
                }
                else
                {
                    var token = await _signInManager.UserManager.GeneratePasswordResetTokenAsync(user);
                    var callbackUrl = Url.Action("ResetPassword", "Account", new { UserId = user.Id, Token = token }, protocol: Request.Scheme);

                    var resetPasswordEmailNotification = new ResetPasswordEmailNotification(WorkContext.CurrentStore.Id, WorkContext.CurrentLanguage)
                    {
                        Url = callbackUrl,
                        Sender = WorkContext.CurrentStore.Email,
                        Recipient = GetUserEmail(user)
                    };

                    var sendingResult = await _platformNotificationApi.SendNotificationAsync(resetPasswordEmailNotification.ToNotificationDto());
                    if (sendingResult.IsSuccess != true)
                    {
                        ModelState.AddModelError("form", sendingResult.ErrorMessage);
                    }
                }
            }
            else
            {
                ModelState.AddModelError("form", "User not found");
            }

            return View("customers/forgot_password", WorkContext);
        }

        [HttpGet("forgotlogin")]
        [AllowAnonymous]
        public ActionResult ForgotLogin()
        {
            return View("customers/forgot_login", WorkContext);
        }

        [HttpPost("forgotlogin")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotLogin(ForgotPassword formModel)
        {
            var user = await _signInManager.UserManager.FindByEmailAsync(formModel.Email);
            if (user != null)
            {
                var remindUserNameNotification = new RemindUserNameNotification(WorkContext.CurrentStore.Id, WorkContext.CurrentLanguage)
                {
                    UserName = user.UserName,
                    Sender = WorkContext.CurrentStore.Email,
                    Recipient = GetUserEmail(user)
                };

                var sendingResult = await _platformNotificationApi.SendNotificationAsync(remindUserNameNotification.ToNotificationDto());
                if (sendingResult.IsSuccess != true)
                {
                    ModelState.AddModelError("form", sendingResult.ErrorMessage);
                }
            }
            else
            {
                ModelState.AddModelError("form", "User not found");
            }
            return View("customers/forgot_login", WorkContext);
        }

        [HttpPost("forgotpasswordbycode")]
        [AllowAnonymous]
        public async Task<ActionResult> ResetPasswordByCode(ResetPasswordByCodeModel formModel)
        {
            if (string.IsNullOrEmpty(formModel.Email))
            {
                WorkContext.ErrorMessage = "Error in request";
                return View("error", WorkContext);
            }

            if (string.IsNullOrEmpty(formModel.Code))
            {
                WorkContext.ErrorMessage = "Code could not be empty";
                return View("error", WorkContext);
            }

            if (!_options.UseSmsForPasswordReset)
            {
                WorkContext.ErrorMessage = "Reset password by code is turned off.";
                return View("error", WorkContext);
            }

            var user = await _signInManager.UserManager.FindByEmailAsync(formModel.Email);
            if (user == null)
            {
                WorkContext.ErrorMessage = "User was not found.";
                return View("error", WorkContext);
            }

            var isValidToken = await _signInManager.UserManager.VerifyUserTokenAsync(user, TokenOptions.DefaultPhoneProvider, "ResetPassword", formModel.Code);

            if (!isValidToken)
            {
                WorkContext.ErrorMessage = "Reset password token is invalid or expired";
                return View("error", WorkContext);
            }

            var token = await _signInManager.UserManager.GeneratePasswordResetTokenAsync(user);

            WorkContext.Form = new ResetPassword
            {
                Token = token,
                Email = user.Email,
                UserName = user.UserName
            };

            return View("customers/reset_password", WorkContext);
        }


        [HttpGet("resetpassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ResetPassword(string token, string userId)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(userId))
            {
                WorkContext.ErrorMessage = "Error in URL format";
                return View("error", WorkContext);
            }

            var user = await _signInManager.UserManager.FindByIdAsync(userId);
            if (user == null)
            {
                WorkContext.ErrorMessage = "User was not found.";
                return View("error", WorkContext);
            }

            var isValidToken = await _signInManager.UserManager.VerifyUserTokenAsync(user, _signInManager.UserManager.Options.Tokens.PasswordResetTokenProvider, UserManager<User>.ResetPasswordTokenPurpose, token);

            if (!isValidToken)
            {
                WorkContext.ErrorMessage = "Reset password token is invalid or expired";
                return View("error", WorkContext);
            }

            WorkContext.Form = new ResetPassword
            {
                Token = token,
                Email = user.Email,
                UserName = user.UserName
            };

            return View("customers/reset_password", WorkContext);
        }

        [HttpPost("resetpassword")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPassword formModel)
        {
            if ((string.IsNullOrEmpty(formModel.Email) && string.IsNullOrEmpty(formModel.UserName)) || formModel.Token == null)
            {
                WorkContext.ErrorMessage = "Not enough info for reseting password";
                return View("error", WorkContext);
            }

            if (formModel.Password != formModel.PasswordConfirmation)
            {
                ModelState.AddModelError("form", "Passwords aren't equal");
                WorkContext.Form = formModel;
                return View("customers/reset_password", WorkContext);
            }

            User user = null;
            if (!string.IsNullOrEmpty(formModel.UserName))
            {
                user = await _signInManager.UserManager.FindByNameAsync(formModel.UserName);
            }
            if (user == null && !string.IsNullOrEmpty(formModel.Email))
            {
                user = await _signInManager.UserManager.FindByEmailAsync(formModel.Email);
            }

            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToPage("./ResetPasswordConfirmation");
            }

            var result = await _signInManager.UserManager.ResetPasswordAsync(user, formModel.Token, formModel.Password);

            if (result.Succeeded)
            {
                return View("customers/reset_password_confirmation", WorkContext);
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            WorkContext.Form = formModel;
            return View("customers/reset_password", WorkContext);
        }

        [HttpPost("password")]
        public async Task<ActionResult> ChangePassword(ChangePassword formModel)
        {
            var result = await _signInManager.UserManager.ChangePasswordAsync(WorkContext.CurrentUser, formModel.OldPassword, formModel.NewPassword);

            if (result.Succeeded)
            {
                return StoreFrontRedirect("~/account");
            }
            else
            {
                ModelState.AddModelError("form", result.Errors.FirstOrDefault()?.Description);
                return View("customers/account", WorkContext);
            }
        }

        [HttpGet("phonenumber")]
        public ActionResult UpdatePhoneNumber(string phoneNumber)
        {
            return View("customers/phone_number", new UpdatePhoneNumberModel { PhoneNumber = phoneNumber });
        }

        [HttpPost("phonenumber")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> UpdatePhoneNumber([FromForm]UpdatePhoneNumberModel formModel)
        {
            if (string.IsNullOrEmpty(formModel.PhoneNumber))
            {
                WorkContext.ErrorMessage = "Phone number is not valid";
                WorkContext.Form = formModel;
                return View("customers/phone_number", WorkContext);
            }
            // Generate the token and send it
            var code = await _signInManager.UserManager.GenerateChangePhoneNumberTokenAsync(WorkContext.CurrentUser, formModel.PhoneNumber);
            await _smsSenderFactory().SendSmsAsync(formModel.PhoneNumber, "Your security code is: " + code);

            return StoreFrontRedirect($"customers/phone_number?phoneNumber={formModel.PhoneNumber}");
        }

        [HttpGet("phonenumber/verify")]
        public ActionResult VerifyPhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
            {
                WorkContext.ErrorMessage = "Phone number is not valid";
                return View("error", WorkContext);
            }
            return View("customers/verify_phone", new VerifyPhoneNumberModel { PhoneNumber = phoneNumber });
        }

        [HttpPost("phonenumber/verify")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber([FromForm]VerifyPhoneNumberModel formModel)
        {
            if (string.IsNullOrEmpty(formModel.Code))
            {
                WorkContext.ErrorMessage = "Verification code could not be empty";
                return View("error", WorkContext);
            }

            if (string.IsNullOrEmpty(formModel.PhoneNumber))
            {
                WorkContext.ErrorMessage = "Phone number is not valid";
                return View("error", WorkContext);
            }

            var result = await _signInManager.UserManager.ChangePhoneNumberAsync(WorkContext.CurrentUser, formModel.PhoneNumber, formModel.Code);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(WorkContext.CurrentUser, isPersistent: false);
                return StoreFrontRedirect("~/account");
            }
            // If we got this far, something failed
            WorkContext.ErrorMessage = "Failed to verify phone number";
            return View("customers/verify_phone", formModel);
        }

        [HttpDelete("phonenumber")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemovePhoneNumber()
        {
            var result = await _signInManager.UserManager.SetPhoneNumberAsync(WorkContext.CurrentUser, null);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(WorkContext.CurrentUser, isPersistent: false);
                return StoreFrontRedirect("~/account");
            }

            WorkContext.ErrorMessage = "Cannot remove phone number";
            return View("error", WorkContext);
        }

        [HttpPost("twofactorauthentification")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableTwoFactorAuthentication(EnableTwoFactorAuthenticationModel model)
        {
            await _signInManager.UserManager.SetTwoFactorEnabledAsync(WorkContext.CurrentUser, model.Enabled);
            await _signInManager.SignInAsync(WorkContext.CurrentUser, isPersistent: false);
            return StoreFrontRedirect("~/account");
        }

        private static string GetUserEmail(User user)
        {
            string email = null;
            if (user != null)
            {
                email = user.Email ?? user.UserName;
                if (user.Contact != null)
                {
                    email = user.Contact?.Email ?? email;
                }
            }
            return email;
        }
    }
}
