namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ RC2
    ///////////////////////////////////////////////////////////////////////////
    public class RC2 : SecretKeyFactory
    {
        // конструктор
        public RC2(int[] keySizes) : base(keySizes) {}
        // конструктор
        public RC2() : base(CAPI.KeySizes.Range(1, 128)) {}
    
        // ограничить размер ключей
        public override SecretKeyFactory Narrow(int[] keySizes) 
        { 
            // ограничить размер ключей
            return new RC2(keySizes); 
        }
    }
}
