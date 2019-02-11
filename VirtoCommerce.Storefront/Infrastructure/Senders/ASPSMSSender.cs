using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace VirtoCommerce.Storefront.Infrastructure.Senders
{
    public class AspsmsSender : ISmsSender
    {
        private readonly SMSoptions _options;  // set only via Secret Manager

        public AspsmsSender(IOptions<SMSoptions> optionsAccessor)
        {
            _options = optionsAccessor.Value;
        }

        public Task SendSmsAsync(string number, string message)
        {
            var SMSSender = new ASPSMS.SMS();

            SMSSender.Userkey = _options.SMSAccountIdentification;
            SMSSender.Password = _options.SMSAccountPassword;
            SMSSender.Originator = _options.SMSAccountFrom;

            SMSSender.AddRecipient(number);
            SMSSender.MessageData = message;

            SMSSender.SendTextSMS();

            return Task.FromResult(0);
        }
    }
}
