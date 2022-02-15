namespace Aladdin.CAPI.GOST.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ ГОСТ 28147-89
    ///////////////////////////////////////////////////////////////////////////
    public class GOST28147 : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new GOST28147(); 

        // размер ключей
	    public override int[] KeySizes { get { return new int[] { 32 }; }}
    }
}
