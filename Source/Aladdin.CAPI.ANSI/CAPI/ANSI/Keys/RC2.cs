namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ RC2
    ///////////////////////////////////////////////////////////////////////////
    public class RC2 : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new RC2(); 

        // размер ключей
	    public override int[] KeySizes { get { return CAPI.KeySizes.Range(1, 128); }}
    }
}
