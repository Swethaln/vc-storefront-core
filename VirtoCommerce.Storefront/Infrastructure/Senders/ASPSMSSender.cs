using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace VirtoCommerce.Storefront.Infrastructure.Senders
{
    public class AspsmsSender : ISmsSender
    {
        private readonly SmsProviderOptions _options;  // set only via Secret Manager

        public AspsmsSender(IOptions<SmsProviderOptions> optionsAccessor)
        {
            _options = optionsAccessor.Value;
        }

        public Task SendSmsAsync(string number, string message)
        {
            var SMSSender = new ASPSMS.SMS();

            SMSSender.Userkey = _options.SmsAccountIdentification;
            SMSSender.Password = _options.SmsAccountPassword;
            SMSSender.Originator = _options.SmsAccountFrom;

            SMSSender.AddRecipient(number);
            SMSSender.MessageData = message;

            SMSSender.SendTextSMS();

            return Task.FromResult(0);
        }
    }
}
