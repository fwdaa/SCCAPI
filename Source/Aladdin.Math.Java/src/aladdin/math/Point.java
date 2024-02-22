package aladdin.math;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Точка на эллиптической кривой
///////////////////////////////////////////////////////////////////////////
public final class Point<E> implements Serializable
{
    private static final long serialVersionUID = 7857502039354720698L;
    
    // бесконечно удаленная точка
    @SuppressWarnings({"unchecked", "rawtypes"}) 
    public static final Point INFINITY = new Point(); 

    // координаты точки
    private final E x; private final E y;
    
    // конструктор
    public Point(E x, E y) { this.x = x; this.y = y; }
    // конструктор
    private Point() { this.x = null; this.y = null; }
    
    // координаты точки
    public final E x() { return x; }
    public final E y() { return y; }

    // сравнение точек
    public final boolean equals(Point<E> other)
    {
        // проверить совпадение ссылок
        if (this == other) return true; 
        
        // проверить на бесконечность
        if (this == INFINITY) return false; 
        
		// сравнить координаты точек
		return x.equals(other.x) && y.equals(other.y);
    }
    @SuppressWarnings({"unchecked"}) 
    @Override public boolean equals(Object other)
    {
    	// проверить совпадение экземпляров
		if (other == this) return true;
        
        // проверить тип объекта
        if (!(other instanceof Point)) return false; 

		// сравнить точки
		return equals((Point<E>)other);
    }
    @Override public int hashCode()
    {
		// проверить на бесконечность 
    	if (this == INFINITY) return 0;

		// получить хэш-код объекта
		return x.hashCode() ^ y.hashCode();
    }
}