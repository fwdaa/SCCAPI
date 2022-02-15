namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ AES
    ///////////////////////////////////////////////////////////////////////////
    public class AES : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new AES(); 

        // размер ключей
	    public override int[] KeySizes { get { return new int[] { 16, 24, 32 }; }}
    }
}
