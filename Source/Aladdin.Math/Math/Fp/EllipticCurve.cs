using System; 

namespace Aladdin.Math.Fp
{
    ///////////////////////////////////////////////////////////////////////
    // Эллиптическая кривая
    ///////////////////////////////////////////////////////////////////////
    public class EllipticCurve : Math.ElliticCurve<BigInteger, Field>
    {
        // коэффициенты эллиптической кривой
        private Field field; private BigInteger a; private BigInteger b;

        // конструктор
        public EllipticCurve(Field field, BigInteger a, BigInteger b)
        {
    	    // сохранить переданные параметры
    	    this.field = field; this.a = a; this.b = b;
        }
        // коэффициенты эллиптической кривой
        public override Field      Field { get { return field; }}
        public override BigInteger A     { get { return a;     }}
        public override BigInteger B     { get { return b;     }}

        ///////////////////////////////////////////////////////////////////////
        // Проверить принадлежность кривой
        ///////////////////////////////////////////////////////////////////////
        public override bool IsPoint(Point<BigInteger> P) 
        {
            // вычислить L = Y^2
            if (IsZero(P)) return true; BigInteger L = field.Sqr(P.Y); 
        
    	    // вычислить R = X^2 + a
            BigInteger R = field.Add(field.Sqr(P.X), a);

            // сравнить Y^2 и X^3 + aX + b
		    return L.Equals(field.Add(field.Product(R, P.X), b));
        }
        // вычислить дополнительный бит при сжатии
        public override int Compress(Point<BigInteger> P)
        {
            // проверить корректность параметров
            if (IsZero(P)) throw new ArgumentException();

            // вычислить дополнительный бит
            return P.Y.TestBit(0) ? 1 : 0; 
        }
        // вычислить точку кривой при расжатии
        public override Point<BigInteger> Decompress(BigInteger x, int y0)
        {
            // вычислить alpha = X^3 + aX + b
            BigInteger alpha = field.Add(field.Product(field.Add(field.Sqr(x), a), x), b); 
        
            // вычислить beta = квадратный корень из alpha
            BigInteger beta = field.Sqrt(alpha); 
        
            // проверить наличие корней
            if (beta == null) throw new ArithmeticException(); 
        
            // вычислить координату Y точки
            BigInteger y = (y0 == (beta.TestBit(0) ? 1 : 0)) ? beta : field.Negate(beta); 
        
            // вернуть точку на эллиптической кривой
            return new Point<BigInteger>(x, y); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Операции с точкой на эллиптической кривой
        ///////////////////////////////////////////////////////////////////////
        public override Point<BigInteger> Add(Point<BigInteger> P, Point<BigInteger> Q)
        {
            // проверить на бесконечность
		    if (IsZero(Q)) return P; if (IsZero(P)) return Q;

		    // выполнить сложение для частного случая
		    if (P.X.Equals(Q.X)) return (P.Y.Equals(Q.Y)) ? Twice(P) : Zero;

            // вычислить deltaX = Q.x - P.x и deltaY = Q.y - P.y
		    BigInteger deltaX = field.Subtract(Q.X, P.X);
		    BigInteger deltaY = field.Subtract(Q.Y, P.Y);

		    // вычислить gamma = deltaY / deltaX
		    BigInteger gamma = field.Divide(deltaY, deltaX);

		    // вычислить x3 = gamma^2 - P.X - Q.X
		    BigInteger x3 = field.Subtract(field.Subtract(field.Sqr(gamma), P.X), Q.X);
        
		    // вычислить y3 = gamma * (P.X - x3) - P.Y
		    BigInteger y3 = field.Subtract(field.Product(gamma, field.Subtract(P.X, x3)), P.Y);
        
		    // вернуть результат сложения
		    return new Point<BigInteger>(x3, y3);
        }
        // удвоение точки
        public override Point<BigInteger> Twice(Point<BigInteger> P)
        {
            // проверить на бесконечность и нулевую точку
		    if (IsZero(P)) return P; if (field.IsZero(P.Y)) return Zero;
        
		    // вычислить x^2
            BigInteger squareX = field.Sqr(P.X); 

		    // вычислить gamma = (3x^2 + a) / 2y
		    BigInteger gamma = field.Divide(
                field.Add(field.Add(field.Twice(squareX), squareX), a), 
                field.Twice(P.Y)
            );
		    // вычислить x2 = gamma^2 - 2 x 
		    BigInteger x2 = field.Subtract(field.Sqr(gamma), field.Twice(P.X));
        
		    // вычислить y2 = gamma * (x - x2) - y
		    BigInteger y2 = field.Subtract(
                field.Product(gamma, field.Subtract(P.X, x2)), P.Y
            );
		    // вернуть результат удвоения
		    return new Point<BigInteger>(x2, y2);
        }
        // вычислить противоположную точку
        public override Point<BigInteger> Negate(Point<BigInteger> P)
        {
            // вычислить противоположную точку
		    return new Point<BigInteger>(P.X, field.Negate(P.Y));
        }
    }
}