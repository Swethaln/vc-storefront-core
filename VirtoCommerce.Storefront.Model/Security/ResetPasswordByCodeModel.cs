using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class ResetPasswordByCodeModel
    {
        [Required]
        [FromForm(Name = "customer[email]")]
        public string Email { get; set; }
        [Required]
        [FromForm(Name = "customer[code]")]
        public string Code { get; set; }

    }
}
