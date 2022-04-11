namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ RC5
    ///////////////////////////////////////////////////////////////////////////
    public class RC5 : SecretKeyFactory
    {
        // конструктор
        public RC5(int[] keySizes) : base(keySizes) {}
        // конструктор
        public RC5() : base(CAPI.KeySizes.Range(1, 256)) {}
    
        // ограничить размер ключей
        public override SecretKeyFactory Narrow(int[] keySizes) 
        { 
            // ограничить размер ключей
            return new RC5(keySizes); 
        }
    }
}
