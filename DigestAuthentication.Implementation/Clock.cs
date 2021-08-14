using System;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    public interface IClock
    {
        DateTime UtcNow { get; }
    }

    internal class Clock : IClock
    {
        public DateTime UtcNow => DateTime.UtcNow;
    }
}
