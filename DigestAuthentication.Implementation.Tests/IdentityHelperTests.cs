using FlakeyBit.DigestAuthentication.Implementation;
using NUnit.Framework;

namespace DigestAuthentication.Implementation.Tests;

public class IdentityHelperTests
{
    [Test]
    public void GeneratedIdentityShouldHaveExpectedClaims()
    {
        var claimsIdentity = IdentityHelper.CreateIdentityForUsername("a_user");
        Assert.That(claimsIdentity.Name, Is.EqualTo("a_user"));
        Assert.That(claimsIdentity.Claims.Single(c => c.Type == DigestAuthImplementation.DigestAuthenticationClaimName).Value, Is.EqualTo("a_user"));
    }
}