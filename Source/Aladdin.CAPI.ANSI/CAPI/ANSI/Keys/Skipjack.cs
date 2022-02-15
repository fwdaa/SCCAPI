namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ Skipjack
    ///////////////////////////////////////////////////////////////////////////
    public class Skipjack : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new Skipjack(); 

        // размер ключей
	    public override int[] KeySizes { get { return new int[] { 10 }; }}
    }
}
