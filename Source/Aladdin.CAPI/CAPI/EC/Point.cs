using System; 

namespace Aladdin.CAPI.EC
{
    ///////////////////////////////////////////////////////////////////////////
    // Точка на эллиптической кривой
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class Point : Math.Point<Math.BigInteger>
    {
        // бесконечно удаленная точка
        public new static readonly Point Infinity = new Point(); 

        // конструктор
        public Point(Math.BigInteger x, Math.BigInteger y) : base(x, y) {}
        // конструктор
        private Point() : base() {}
    }
}
