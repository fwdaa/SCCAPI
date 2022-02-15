namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ RC5
    ///////////////////////////////////////////////////////////////////////////
    public class RC5 : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new RC5(); 

        // размер ключей
	    public override int[] KeySizes { get { return CAPI.KeySizes.Range(1, 256); }}
    }
}
