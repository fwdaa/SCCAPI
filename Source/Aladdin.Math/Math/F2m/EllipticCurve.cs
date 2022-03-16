using System; 

namespace Aladdin.Math.F2m
{
    ///////////////////////////////////////////////////////////////////////
    // Эллиптическая кривая
    ///////////////////////////////////////////////////////////////////////
    [Serializable]
    public class EllipticCurve : Math.ElliticCurve<Vector, Field>
    {
        // коэффициенты эллиптической кривой
        private Field field; private Vector a; private Vector b;

        // конструктор
        public EllipticCurve(Field field, Vector a, Vector b)
        {
    	    // сохранить переданные параметры
    	    this.field = field; this.a = a; this.b = b;
        }
        // коэффициенты эллиптической кривой
        public override Field  Field { get { return field; }}
        public override Vector A     { get { return a;     }}
        public override Vector B     { get { return b;     }}

        ///////////////////////////////////////////////////////////////////////
        // Проверить принадлежность кривой
        ///////////////////////////////////////////////////////////////////////
        public override bool IsPoint(Point<Vector> P) 
        {
            // вычислить XY
            if (IsZero(P)) return true; Vector xy = field.Product(P.X, P.Y);
        
    	    // вычислить Y^2 и X^2
		    Vector y2 = field.Sqr(P.Y); Vector x2 = field.Sqr(P.X);
        
		    // выполнить X^3 + aX^2
		    Vector x3_ax2 = field.Product(x2, field.Add(P.X, a)); 

		    // сравнить Y^2 + YX и X^3 + aX^2 + b
		    return field.Add(y2, xy).Equals(field.Add(x3_ax2, b));
        }
        // вычислить дополнительный бит при сжатии
        public override int Compress(Point<Vector> P)
        {
            // проверить корректность параметров
            if (IsZero(P)) throw new ArgumentException(); 
        
            // проверить на нулевую координату
            if (field.IsZero(P.X)) return 0; 
        
            // вычислить YX^{-1}
            Vector product = field.Product(P.Y, field.Invert(P.X)); 
        
            // вычислить дополнительный бит
            return product[field.M - 1]; 
        }
        // вычислить точку кривой при расжатии
        public override Point<Vector> Decompress(Vector x, int y0)
        {
            // для нулевой координаты x вычислить y = b^{2^{m-1}}
            if (field.IsZero(x)) return new Point<Vector>(x, field.Sqrt(b)); 
        
            // вычислить beta = x + a + bx^{-2}
            Vector beta = field.Add(field.Add(x, a), field.Divide(b, field.Sqr(x))); 
        
            // найти решение z уравнения z^2 + z = beta
            Vector z = field.QuadraticRoot(beta); 
        
            // проверить наличие корней
            if (z == null) throw new ArithmeticException(); 
        
            // при необходимости выбрать другой корень
            if (z[field.M - 1] != y0) z = field.Add(z, field.One); 
        
            // вернуть точку эллиптической кривой
            return new Point<Vector>(x, field.Product(x, z)); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Операции с точкой на эллиптической кривой
        ///////////////////////////////////////////////////////////////////////
        public override Point<Vector> Add(Point<Vector> P, Point<Vector> Q)
        {
		    // проверить на бесконечность
            if (IsZero(Q)) return P; if (IsZero(P)) return Q; 
        
		    // выполнить сложение для частного случая
		    if (P.X.Equals(Q.X)) return (P.Y.Equals(Q.Y)) ? Twice(P) : Zero;

            // вычислить deltaX = P.x + Q.x и deltaY = P.y + Q.y
		    Vector deltaX = field.Add(P.X, Q.X);
		    Vector deltaY = field.Add(P.Y, Q.Y);

		    // вычислить gamma = deltaY / deltaX
		    Vector gamma = field.Divide(deltaY, deltaX);

		    // вычислить x3 = gamma^2 + gamma + deltaX + a
		    Vector x3 = field.Add(a, field.Add(deltaX, 
                field.Add(field.Sqr(gamma), gamma)
            ));
		    // вычислить y3 = gamma * (P.x + x3) + x3 + P.y
		    Vector y3 = field.Add(P.Y, field.Add(x3, 
                field.Product(gamma, field.Add(P.X, x3))
            ));
		    // вернуть результат сложения
		    return new Point<Vector>(x3, y3);
        }
        // удвоение точки
        public override Point<Vector> Twice(Point<Vector> P)
        {
            // проверить на бесконечность и нулевую точку 
		    if (IsZero(P)) return P; if (field.IsZero(P.X)) return Zero;
        
		    // вычислить gamma = x + y / x
		    Vector gamma = field.Add(P.X, field.Divide(P.Y, P.X));

		    // вычислить x2 = gamma^2 + gamma + a 
		    Vector x2 = field.Add(a, field.Add(gamma, field.Sqr(gamma)));
        
		    // вычислить y2 = x^2 + gamma x2 + x2
		    Vector y2 = field.Add(x2, field.Add(
                field.Product(gamma, x2), field.Sqr(P.X)
            )); 
		    // вернуть результат удвоения
		    return new Point<Vector>(x2, y2);
        }
        // вычислить противоположную точку
        public override Point<Vector> Negate(Point<Vector> P)
        {
            // вычислить противоположную точку
		    return new Point<Vector>(P.X, field.Add(P.X, P.Y));
        }
    }
}
