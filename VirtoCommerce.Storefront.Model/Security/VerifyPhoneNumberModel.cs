using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class VerifyPhoneNumberModel
    {
        [FromForm(Name = "customer[code]")]
        public string Code { get; set; }

        [FromForm(Name = "customer[phoneNumber]")]
        public string PhoneNumber { get; set; }
    }
}
