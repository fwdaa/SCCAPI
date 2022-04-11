namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ AES
    ///////////////////////////////////////////////////////////////////////////
    public class AES : SecretKeyFactory
    {
        // конструктор
        public AES(int[] keySizes) : base(keySizes) {}
        // конструктор
        public AES() : base(new int[] { 16, 24, 32 }) {}
    
        // ограничить размер ключей
        public override SecretKeyFactory Narrow(int[] keySizes) 
        { 
            // ограничить размер ключей
            return new AES(keySizes); 
        }
    }
}
