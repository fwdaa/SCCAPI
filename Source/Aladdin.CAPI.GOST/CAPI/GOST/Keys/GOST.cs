namespace Aladdin.CAPI.GOST.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ ГОСТ 28147-89
    ///////////////////////////////////////////////////////////////////////////
    public class GOST : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new GOST(); 

        // конструктор
        public GOST() : base(new int[] {32}) {}
    }
}
