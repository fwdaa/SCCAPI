namespace Aladdin.CAPI.STB.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ СТБ 34.101
    ///////////////////////////////////////////////////////////////////////////
    public class STB34101 : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new STB34101(); 

        // размер ключей
	    public override int[] KeySizes { get { return new int[] { 16, 24, 32 }; }}
    }
}
