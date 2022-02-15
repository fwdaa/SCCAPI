package aladdin.math;

///////////////////////////////////////////////////////////////////////
// Эллиптическая кривая
///////////////////////////////////////////////////////////////////////
public abstract class EllipticCurve<E, F extends Field<E>> extends AddGroup<Point<E>> 
{
    // коэффициенты эллиптической кривой
    public abstract F field();
    public abstract E a    ();
    public abstract E b    ();
    
    // признак принадлежности эллиптической кривой
    public abstract boolean isPoint(Point<E> P);
    
    ///////////////////////////////////////////////////////////////////
    // Сравнение эллиптических кривых
    ///////////////////////////////////////////////////////////////////
    public final boolean equals(EllipticCurve<E, F> other)
    {
    	// сравнить параметры эллиптической кривой
    	return a().equals(other.a()) && b().equals(other.b());
    }
    @SuppressWarnings({"unchecked"}) 
    @Override public boolean equals(Object other)
    {
    	// проверить совпадение экземпляров
    	if (other == this) return true;
        
        // проверить тип объекта
        if (!(other instanceof EllipticCurve)) return false; 
        
		// сравнить элииптические кривые
		return equals((EllipticCurve<E, F>)other);
    }
    @Override public int hashCode()
    {
    	// получить хэш-код объекта
    	return field().hashCode() ^ a().hashCode() ^ b().hashCode();
    }
    ////////////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ////////////////////////////////////////////////////////////////////////////
    
    // бесконечная точка эллиптической кривой
    @SuppressWarnings({"unchecked"}) 
    @Override public final Point<E> zero() { return Point.INFINITY; }
    // признак нулевого элемента
    @Override public final boolean isZero(Point<E> P) { return P == zero(); }
    
    ////////////////////////////////////////////////////////////////////////////
    // Кодирование точек эллиптической кривой
    ////////////////////////////////////////////////////////////////////////////
    
    // вычислить дополнительный бит при сжатии
    public abstract int compress(Point<E> P); 
    // вычислить точку кривой при расжатии
    public abstract Point<E> decompress(E x, int y0); 
}
