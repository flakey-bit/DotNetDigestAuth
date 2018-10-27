using System;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace FlakeyBit.DigestAuthMiddleware.AspNetClassic
{
    public class DigestAuthenticationMiddleware : OwinMiddleware
    {
        public DigestAuthenticationMiddleware(OwinMiddleware next) : base(next) {
        }

        public override Task Invoke(IOwinContext context) {
            throw new NotImplementedException();
        }
    }
}
