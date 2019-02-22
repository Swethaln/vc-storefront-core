using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace VirtoCommerce.Storefront.Infrastructure.Senders
{
    public class TwilioSender : ISmsSender
    {
        private readonly SmsProviderOptions _options;  // set only via Secret Manager
        public TwilioSender(IOptions<SmsProviderOptions> optionsAccessor)
        {
            _options = optionsAccessor.Value;
        }
        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.
            // Your Account SID from twilio.com/console
            var accountSid = _options.SmsAccountIdentification;
            // Your Auth Token from twilio.com/console
            var authToken = _options.SmsAccountPassword;

            TwilioClient.Init(accountSid, authToken);

            return MessageResource.CreateAsync(
              to: new PhoneNumber(number),
              from: new PhoneNumber(_options.SmsAccountFrom),
              body: message);
        }
    }
}
