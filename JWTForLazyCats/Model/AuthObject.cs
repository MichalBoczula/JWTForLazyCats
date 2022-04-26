namespace JWTForLazyCats.Model
{
    public class AuthObject
    {
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}