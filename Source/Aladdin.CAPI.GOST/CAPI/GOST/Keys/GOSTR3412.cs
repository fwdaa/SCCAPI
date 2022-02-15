namespace Aladdin.CAPI.GOST.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ ГОСТ Р34.12
    ///////////////////////////////////////////////////////////////////////////
    public class GOSTR3412 : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new GOSTR3412(); 

        // размер ключей
	    public override int[] KeySizes { get { return new int[] { 32 }; }}
    }
}
