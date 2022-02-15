package aladdin.math.Fp;
import aladdin.math.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////
// Эллиптическая кривая
///////////////////////////////////////////////////////////////////////
public class EllipticCurve extends aladdin.math.EllipticCurve<BigInteger, Field>
{
    // коэффициенты эллиптической кривой
    private final Field field; private final BigInteger a; private final BigInteger b;

    // конструктор
    public EllipticCurve(Field field, BigInteger a, BigInteger b)
    {
    	// сохранить переданные параметры
    	this.field = field; this.a = a; this.b = b;
    }
    // коэффициенты эллиптической кривой
    @Override public final Field      field() { return field; }
    @Override public final BigInteger a    () { return a;     }
    @Override public final BigInteger b    () { return b;     }

    ///////////////////////////////////////////////////////////////////////
    // Проверить принадлежность кривой
    ///////////////////////////////////////////////////////////////////////
    @Override public boolean isPoint(Point<BigInteger> P) 
    {
    	// вычислить L = Y^2
        if (isZero(P)) return true; BigInteger L = field.sqr(P.y());
        
    	// вычислить R = X^2 + a
        BigInteger R = field.add(field.sqr(P.x()), a);

        // сравнить Y^2 и X^3 + aX + b
		return L.equals(field.add(field.product(R, P.x()), b));
    }
    // вычислить дополнительный бит при сжатии
    @Override public int compress(Point<BigInteger> P)
    {
        // проверить корректность параметров
        if (isZero(P)) throw new IllegalArgumentException(); 
        
        // вычислить дополнительный бит
        return P.y().testBit(0) ? 1 : 0; 
    }
    // вычислить точку кривой при расжатии
    @Override public Point<BigInteger> decompress(BigInteger x, int y0)
    {
        // вычислить alpha = X^3 + aX + b
        BigInteger alpha = field.add(field.product(field.add(field.sqr(x), a), x), b); 
        
        // вычислить beta = квадратный корень из alpha
        BigInteger beta = field.sqrt(alpha); 
        
        // проверить наличие корней
        if (beta == null) throw new ArithmeticException(); 
        
        // вычислить координату Y точки
        BigInteger y = (y0 == (beta.testBit(0) ? 1 : 0)) ? beta : field.negate(beta); 
        
        // вернуть точку на эллиптической кривой
        return new Point<BigInteger>(x, y); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Операции с точкой на эллиптической кривой
    ///////////////////////////////////////////////////////////////////////
    @Override public Point<BigInteger> add(Point<BigInteger> P, Point<BigInteger> Q)
    {
        // проверить на бесконечность
		if (isZero(Q)) return P; if (isZero(P)) return Q; 

		// выполнить сложение для частного случая
		if (P.x().equals(Q.x())) return (P.y().equals(Q.y())) ? twice(P) : zero();

        // вычислить deltaX = Q.x - P.x и deltaY = Q.y - P.y
		BigInteger deltaX = field.subtract(Q.x(), P.x());
		BigInteger deltaY = field.subtract(Q.y(), P.y());

		// вычислить gamma = deltaY / deltaX
		BigInteger gamma = field.divide(deltaY, deltaX);

		// вычислить x3 = gamma^2 - P.X - Q.X
		BigInteger x3 = field.subtract(field.subtract(field.sqr(gamma), P.x()), Q.x());
        
		// вычислить y3 = gamma * (P.X - x3) - P.Y
		BigInteger y3 = field.subtract(field.product(gamma, field.subtract(P.x(), x3)), P.y());
        
		// вернуть результат сложения
		return new Point<BigInteger>(x3, y3);
    }
    // удвоение точки
    @Override public Point<BigInteger> twice(Point<BigInteger> P)
    {
        // проверить на бесконечность и нулевую точку
		if (isZero(P)) return P; if (field.isZero(P.y())) return zero();
        
		// вычислить x^2
        BigInteger squareX = field.sqr(P.x()); 

		// вычислить gamma = (3x^2 + a) / 2y
		BigInteger gamma = field.divide(
            field.add(field.add(field.twice(squareX), squareX), a), 
            field.twice(P.y())
        );
		// вычислить x2 = gamma^2 - 2 x 
		BigInteger x2 = field.subtract(field.sqr(gamma), field.twice(P.x()));
        
		// вычислить y2 = gamma * (x - x2) - y
		BigInteger y2 = field.subtract(
            field.product(gamma, field.subtract(P.x(), x2)), P.y()
        );
		// вернуть результат удвоения
		return new Point<BigInteger>(x2, y2);
    }
    // вычислить противоположную точку
    @Override public Point<BigInteger> negate(Point<BigInteger> P)
    {
        // вычислить противоположную точку
		return new Point<BigInteger>(P.x(), field.negate(P.y()));
    }
}