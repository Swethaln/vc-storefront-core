using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace VirtoCommerce.Storefront.Infrastructure.Senders
{
    public class DummyEmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            return Task.FromResult(0);
        }
    }
}
