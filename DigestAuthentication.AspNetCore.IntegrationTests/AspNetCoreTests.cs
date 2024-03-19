using FlakeyBit.DigestAuthentication.AspNetCore;
using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using NUnit.Framework;
using System.Linq;
using System.Text.Encodings.Web;

namespace DigestAuthentication.AspNetCore.IntegrationTests
{
    [TestFixture]
    public class AspNetCoreTests
    {
        private DigestAuthenticationHandler _sut;

        [SetUp]
        public void SetUp()
        {
            var hashedSecretProvider = Substitute.For<IUsernameHashedSecretProvider>();
            var clock = Substitute.For<ISystemClock>();
            var loggerFactory = Substitute.For<ILoggerFactory>();
            _sut = new DigestAuthenticationHandler(null, loggerFactory, null, clock, hashedSecretProvider);
        }

        [Test]
        public void Basic_login_scenario()
        {
            var claimsIdentity = _sut.CreateIdentityFromValidatedUserName("a_user", "digest");
            Assert.That(claimsIdentity.Name, Is.EqualTo("a_user"));
            Assert.That(claimsIdentity.Claims.Single(c => c.Type == DigestAuthImplementation.DigestAuthenticationClaimName).Value, Is.EqualTo("a_user"));
        }
    }
}
