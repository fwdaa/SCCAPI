namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ Skipjack
    ///////////////////////////////////////////////////////////////////////////
    public class Skipjack : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new Skipjack(); 

        // конструктор
        public Skipjack() : base(new int[] {10}) {}
    }
}
