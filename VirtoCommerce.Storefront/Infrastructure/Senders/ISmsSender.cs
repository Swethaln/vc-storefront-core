using System.Threading.Tasks;

namespace VirtoCommerce.Storefront.Infrastructure.Senders
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
