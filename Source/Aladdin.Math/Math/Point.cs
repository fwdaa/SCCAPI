using System;

namespace Aladdin.Math 
{
    ///////////////////////////////////////////////////////////////////////////
    // Точка на эллиптической кривой
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class Point<E> : IEquatable<Point<E>> where E : class
    {
        // бесконечно удаленная точка
        public static readonly Point<E> Infinity = new Point<E>(); 

        // координаты точки
        private E x; private E y;

        // конструктор
        public Point(E x, E y) { this.x = x; this.y = y; }
        // конструктор
        protected Point() { this.x = null; this.y = null; }
    
        // координаты точки
        public E X { get { return x; }}
        public E Y { get { return y; }}

        public bool Equals(Point<E> other)
        {
            // проверить совпадение ссылок
            if (Object.ReferenceEquals(this, other)) return true; 

            // проверить на бесконечно удаленную точку
		    if (Object.ReferenceEquals(this, Infinity)) return false;

		    // сравнить координаты точек
		    return x.Equals(other.x) && y.Equals(other.y);
        }
        public override bool Equals(object other)
        {
    	    // проверить совпадение экземпляров
		    if (other == this) return true;
        
            // проверить тип объекта
            if (!(other is Point<E>)) return false; 

		    // сравнить точки
		    return Equals((Point<E>)other);
        }
        public override int GetHashCode()
        {
		    // проверить на бесконечность 
    	    if (Object.ReferenceEquals(this, Infinity)) return 0;

		    // получить хэш-код объекта
		    return x.GetHashCode() ^ y.GetHashCode();
        }
    }
}
