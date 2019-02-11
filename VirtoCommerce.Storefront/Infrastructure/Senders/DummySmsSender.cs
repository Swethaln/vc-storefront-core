using System.Threading.Tasks;

namespace VirtoCommerce.Storefront.Infrastructure.Senders
{
    public class DummySmsSender : ISmsSender
    {
        public Task SendSmsAsync(string number, string message)
        {
            return Task.FromResult(0);
        }
    }
}
