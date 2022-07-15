using System;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using AspNetCoreApp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using NUnit.Framework;
using FlakeyBit.DigestAuthentication.Implementation;
using DigestAuthenticationUtils = FlakeyBit.DigestAuthentication.Implementation.DigestAuthentication;
using FlakeyBit.DigestAuthentication.AspNetCore;

namespace DigestAuthentication.AspNetCore.IntegrationTests
{
    [TestFixture]
    public class IntegrationTests
    {
        private const string RequestUri = "/api/values";
        private readonly DateTimeOffset _startTime = DateTimeOffset.Parse("2019-09-26T00:21:23.0000000Z");
        private WebAppFactory _webAppFactory;
        private Mock<ISystemClock> _systemClockMock;

        [SetUp]
        public void SetUp() {
            _systemClockMock = new Mock<ISystemClock>(MockBehavior.Strict);
            _webAppFactory = new WebAppFactory(_systemClockMock.Object);
        }

        [Test]
        public async Task RequestWithNoAuthorizationHeaderReturnsWwwAuthenticateChallenge() {
            _systemClockMock.Setup(c => c.UtcNow).Returns(_startTime);

            var client = _webAppFactory.CreateClient();
            var response = await client.GetAsync(RequestUri);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            var authHeader = response.Headers.WwwAuthenticate.Single();
            Assert.That(authHeader.Scheme, Is.EqualTo("Digest"));           
            Assert.That(authHeader.Parameter, Is.EqualTo("realm=\"some-realm\", nonce=\"2019-09-26 00:21:23.000000Z 1f36bf2dae9ddb750a644c9994ffffe1\", qop=\"auth\", algorithm=MD5"));

            var content = await response.Content.ReadAsStringAsync();
            Assert.That(content, Is.Empty);
        }

        [Test]
        public async Task ARequestWithValidChallengeResponseReturnsContent() {
            _systemClockMock.Setup(c => c.UtcNow).Returns(_startTime.AddSeconds(30));

            // Ugh, I wanted to use HttpClient's support for Digest auth,
            // but couldn't make it work due to the WebApplicationFactory magic
            var client = _webAppFactory.CreateClient();
            const string username = "eddie";
            const string password = "starwars123";
            const string realm = "some-realm";
            const string nonce = "2019-09-26 00:21:23.000000Z 1f36bf2dae9ddb750a644c9994ffffe1";
            const string nonceCounter = "1";
            const string clientNonce = "1";

            var expectedHash = GenerateExpectedHash("GET", RequestUri, username, password, realm, nonce, nonceCounter, clientNonce);

            var digestHeaderParts = new[] {
                $"username=\"{username}\"",
                $"realm=\"{realm}\"",
                $"nonce=\"{nonce}\"",
                $"uri=\"{RequestUri}\"",
                $"nc={nonceCounter}",
                $"cnonce=\"{clientNonce}\"",
                $"response=\"{expectedHash}\""
            };

            var digestHeader = string.Join(",", digestHeaderParts);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Digest", digestHeader);

            var response = await client.GetAsync(RequestUri);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var content = await response.Content.ReadAsStringAsync();
            Assert.That(content, Is.EqualTo("Hello Core!"));
        }

        [Test]
        public async Task DigestValidityDeterminedByMaxNonceAge()
        {
            DateTimeOffset currentTime = _startTime;
            _systemClockMock.Setup(c => c.UtcNow)
            .Returns(() => currentTime);

            var client = _webAppFactory.CreateClient();
            const string username = "eddie";
            const string password = "starwars123";
            const string realm = "some-realm";
            const string nonce = "2019-09-26 00:21:23.000000Z 1f36bf2dae9ddb750a644c9994ffffe1";
            const string nonceCounter = "1";
            const string clientNonce = "1";

            var expectedHash = GenerateExpectedHash("GET", RequestUri, username, password, realm, nonce, nonceCounter, clientNonce);

            var digestHeaderParts = new[] {
                $"username=\"{username}\"",
                $"realm=\"{realm}\"",
                $"nonce=\"{nonce}\"",
                $"uri=\"{RequestUri}\"",
                $"nc={nonceCounter}",
                $"cnonce=\"{clientNonce}\"",
                $"response=\"{expectedHash}\""
            };

            var digestHeader = string.Join(",", digestHeaderParts);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Digest", digestHeader);

            // Make initial request at T=0
            currentTime = _startTime;
            var response = await client.GetAsync(RequestUri);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            // T+30, make another request
            currentTime = _startTime.AddSeconds(30);
            response = await client.GetAsync(RequestUri);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            // T+60, make another request
            currentTime = _startTime.AddSeconds(seconds: 60);
            response = await client.GetAsync(RequestUri);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            // T+61, make another request (max nonce age exceeded)
            currentTime = _startTime.AddSeconds(seconds: 61);
            response = await client.GetAsync(RequestUri);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        [TearDown]
        public void TearDown()
        {
            _webAppFactory.Dispose();
        }

        private string GenerateExpectedHash(string requestMethod,
                                            string uri,
                                            string username,
                                            string password,
                                            string realm,
                                            string nonce,
                                            string nonceCounter,
                                            string clientNonce) {
            var a1Hash = DigestAuthenticationUtils.ComputeA1Md5Hash(username, realm, password);

            var a2 = $"{requestMethod}:{uri}";
            var a2Hash = a2.ToMD5Hash();

            return $"{a1Hash}:{nonce}:{nonceCounter}:{clientNonce}:auth:{a2Hash}".ToMD5Hash();
        }
    }

    public class WebAppFactory : WebApplicationFactory<Startup>
    {
        private readonly ISystemClock _systemClock;
        private readonly Action<IServiceCollection> _configureServices;

        public WebAppFactory(ISystemClock systemClock, Action<IServiceCollection> configureServices=null) {
            _systemClock = systemClock;
            _configureServices = configureServices;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder) {
            builder.ConfigureServices(services => {
                services.AddSingleton(_systemClock);
            });

            if (_configureServices != null) {
                builder.ConfigureServices(_configureServices);
            }

            base.ConfigureWebHost(builder);
        }
    }
}