namespace VirtoCommerce.Storefront.Infrastructure
{
    public class SmsProviderOptions
    {
        public string SmsProviderType { get; set; }
        public string SmsAccountIdentification { get; set; }
        public string SmsAccountPassword { get; set; }
        public string SmsAccountFrom { get; set; }
    }
}
