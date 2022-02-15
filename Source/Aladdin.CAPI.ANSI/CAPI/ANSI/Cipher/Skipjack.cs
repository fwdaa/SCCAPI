namespace Aladdin.CAPI.ANSI.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования Skipjack
    ///////////////////////////////////////////////////////////////////////////
    public class Skipjack : BlockCipher
    {
        // конструктор
        public Skipjack(CAPI.Cipher engine, PaddingMode padding) : base(engine, padding) {}
    }
}