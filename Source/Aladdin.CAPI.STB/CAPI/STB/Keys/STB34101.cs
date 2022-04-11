namespace Aladdin.CAPI.STB.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ СТБ 34.101
    ///////////////////////////////////////////////////////////////////////////
    public class STB34101 : SecretKeyFactory
    {
        // конструктор
        public STB34101(int[] keySizes) : base(keySizes) {}
        // конструктор
        public STB34101() : base(new int[] { 16, 24, 32 }) {}
    
        // ограничить размер ключей
        public override SecretKeyFactory Narrow(int[] keySizes) 
        { 
            // ограничить размер ключей
            return new STB34101(keySizes); 
        }
    }
}
