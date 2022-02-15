namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ RC4
    ///////////////////////////////////////////////////////////////////////////
    public class RC4 : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new RC4(); 

        // размер ключей
	    public override int[] KeySizes { get { return CAPI.KeySizes.Range(1, 256); }}
    }
}
