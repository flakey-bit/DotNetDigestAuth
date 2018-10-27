namespace FlakeyBit.DigestAuthentication.Implementation
{
    public class DigestAuthenticationConfiguration
    {
        public string ServerNonceSecret;
        public string Realm = "unknown-realm";
        public long MaxNonceAgeSeconds = 3600;
    }
}