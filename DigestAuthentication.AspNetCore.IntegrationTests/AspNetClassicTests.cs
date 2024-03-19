using FlakeyBit.DigestAuthentication.AspNetClassic;
using FlakeyBit.DigestAuthentication.Implementation;
using NSubstitute;
using NUnit.Framework;
using System.Linq;

namespace DigestAuthentication.AspNetCore.IntegrationTests
{
    [TestFixture]
    public class AspNetClassicTests
    {
        private DigestAuthenticationHandler _sut;

        [SetUp]
        public void SetUp()
        {
            var config = DigestAuthenticationConfiguration.Create("secret", "test-realm");
            var hashedSecretProvider = Substitute.For<IUsernameHashedSecretProvider>();
            var clock = Substitute.For<IClock>();
            _sut = new DigestAuthenticationHandler(config, hashedSecretProvider, clock);
        }

        [Test]
        public void Basic_login_scenario()
        {
            var claimsIdentity = _sut.CreateIdentityFromValidatedUserName("a_user");
            Assert.That(claimsIdentity.Name, Is.EqualTo("a_user"));
            Assert.That(claimsIdentity.Claims.Single(c => c.Type == DigestAuthImplementation.DigestAuthenticationClaimName).Value, Is.EqualTo("a_user"));
        }
    }
}
