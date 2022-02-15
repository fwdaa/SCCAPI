using System; 

////////////////////////////////////////////////////////////////////////////////
// Параметры ключа СТБ 34.101
////////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB34101
{
    public class Parameters : IParameters
    {
        // конструктор 
        public Parameters(EC.CurveFp ec, EC.Point g, Math.BigInteger q)
        {
            // проверить корректность данных
            if (g.X.Signum != 0) throw new NotSupportedException(); 

            this.ec = ec;   // эллиптическая кривая
            this.g  = g;    // базовая точка G
            this.q  = q;    // порядок базовой точки
        }
	    public EC.CurveFp       Curve     { get { return ec;       }} 
	    public EC.Point         Generator { get { return g;        }} 
	    public Math.BigInteger	Order     { get { return q;        }} 
    
        private EC.CurveFp      ec;       // эллиптическая кривая
        private EC.Point        g;        // базовая точка G
        private Math.BigInteger q;        // порядок базовой точки
    }
}
