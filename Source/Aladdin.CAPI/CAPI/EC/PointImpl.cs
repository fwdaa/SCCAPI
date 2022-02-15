using System;

namespace Aladdin.CAPI.EC
{
    ///////////////////////////////////////////////////////////////////////
    // Реализация точки на эллиптической кривой
    ///////////////////////////////////////////////////////////////////////
    internal class PointImpl<E> : Point where E : class
    {
        // точка на эллиптической кривой
        private Math.Point<E> mathPoint; 
    
        // конструктор
        public PointImpl(Math.Point<E> mathPoint, Math.BigInteger x, Math.BigInteger y)
        
            // сохранить переданные параметры
            : base(x, y) { this.mathPoint = mathPoint; }
        
        // точка на эллиптической кривой
        public Math.Point<E> MathPoint { get { return mathPoint; }}
    }
}
