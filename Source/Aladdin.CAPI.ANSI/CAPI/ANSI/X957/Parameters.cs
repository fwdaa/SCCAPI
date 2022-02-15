namespace Aladdin.CAPI.ANSI.X957
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры ключей DSA
    ///////////////////////////////////////////////////////////////////////////
    public class Parameters : IParameters 
    {
        // конструктор
        public Parameters(Math.BigInteger p, Math.BigInteger q, Math.BigInteger g)
        {
            // сохранить переданные параметры
            this.p = p; this.q = q; this.g = g; 
        }
        // параметры ключей 
	    public Math.BigInteger P { get { return p; }} private Math.BigInteger p; 
	    public Math.BigInteger Q { get { return q; }} private Math.BigInteger q;
        public Math.BigInteger G { get { return g; }} private Math.BigInteger g;
    }
}
