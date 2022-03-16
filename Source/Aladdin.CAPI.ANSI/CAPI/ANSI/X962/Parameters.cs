using System; 

namespace Aladdin.CAPI.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // Параметры ключа 
    ////////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class Parameters : IParameters
    {
        private EC.Curve                     curve; // эллиптическая кривая
        private EC.Point                     g;     // базовая точка G
        private Math.BigInteger              n;     // порядок базовой точки
        private Math.BigInteger              h;     // сомножитель
        private ASN1.ISO.AlgorithmIdentifier hash;  // алгоритм хэширования

        // конструктор 
        public Parameters(EC.Curve curve, EC.Point g, 
            Math.BigInteger n, Math.BigInteger h, ASN1.ISO.AlgorithmIdentifier hash)
        {
            this.curve = curve; // эллиптическая кривая
            this.g     = g;     // базовая точка G
            this.n     = n;     // порядок базовой точки
            this.h     = h;     // сомножитель
            this.hash  = hash;  // алгоритм хэширования
        }
        public EC.Curve                        Curve     { get { return curve;  }} 
        public EC.Point                        Generator { get { return g;      }} 
        public Math.BigInteger                 Order     { get { return n;      }} 
        public Math.BigInteger                 Cofactor  { get { return h;      }} 
        public ASN1.ISO.AlgorithmIdentifier    Hash      { get { return hash;   }} 
    }
}
