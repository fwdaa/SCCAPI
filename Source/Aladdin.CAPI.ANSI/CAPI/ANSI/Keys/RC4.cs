namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ RC4
    ///////////////////////////////////////////////////////////////////////////
    public class RC4 : SecretKeyFactory
    {
        // конструктор
        public RC4(int[] keySizes) : base(keySizes) {}
        // конструктор
        public RC4() : base(CAPI.KeySizes.Range(1, 256)) {}
    
        // ограничить размер ключей
        public override SecretKeyFactory Narrow(int[] keySizes) 
        { 
            // ограничить размер ключей
            return new RC4(keySizes); 
        }
    }
}
