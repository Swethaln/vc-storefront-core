using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class ResetPasswordByCodeModel
    {
        [FromForm(Name = "customer[email]")]
        public string Email { get; set; }
        [FromForm(Name = "customer[code]")]
        public string Code { get; set; }

    }
}
