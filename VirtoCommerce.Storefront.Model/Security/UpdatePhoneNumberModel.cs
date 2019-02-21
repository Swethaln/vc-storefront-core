using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class UpdatePhoneNumberModel
    {
        [FromForm(Name = "customer[phoneNumber]")]
        public string PhoneNumber { get; set; }
    }
}
