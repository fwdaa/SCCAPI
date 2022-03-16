using System; 

namespace Aladdin.Math 
{
    ///////////////////////////////////////////////////////////////////////
    // Эллиптическая кривая
    ///////////////////////////////////////////////////////////////////////
    [Serializable]
    public abstract class ElliticCurve<E, F> : GroupAdd<Point<E>>, 
        IEquatable<ElliticCurve<E, F>> where F : IField<E> where E : class
    {
        // коэффициенты эллиптической кривой
        public abstract F Field { get; }
        public abstract E A     { get; }
        public abstract E B     { get; }

        // проверить принадлежность кривой
        public abstract bool IsPoint(Point<E> P); 

        ///////////////////////////////////////////////////////////////////
        // Сравнение эллиптических кривых
        ///////////////////////////////////////////////////////////////////
        public virtual bool Equals(ElliticCurve<E,F> other)
        {
    	    // сравнить параметры эллиптической кривой
    	    return A.Equals(other.A) && B.Equals(other.B);
        }
        public override bool Equals(object other)
        {
    	    // проверить совпадение экземпляров
    	    if (other == this) return true;
        
            // проверить тип объекта
            if (!(other is ElliticCurve<E, F>)) return false; 
        
		    // сравнить элииптические кривые
		    return Equals((ElliticCurve<E, F>)other);
        }
        public override int GetHashCode()
        {
    	    // получить хэш-код объекта
    	    return Field.GetHashCode() ^ A.GetHashCode() ^ B.GetHashCode();
        }
        ////////////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ////////////////////////////////////////////////////////////////////////////
    
        // бесконечная точка эллиптической кривой
        public override Point<E> Zero { get { return Point<E>.Infinity; }}

        // признак нулевого элемента
        public override bool IsZero(Point<E> P) 
        { 
            // признак нулевого элемента
            return Object.ReferenceEquals(P, Zero); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Кодирование точек эллиптической кривой
        ////////////////////////////////////////////////////////////////////////////

        // вычислить дополнительный бит при сжатии
        public abstract int Compress(Point<E> P); 
    
        // вычислить точку кривой при расжатии
        public abstract Point<E> Decompress(E x, int y0); 
    }
}