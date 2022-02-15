package aladdin.math.F2m;
import aladdin.math.*; 

///////////////////////////////////////////////////////////////////////
// Эллиптическая кривая
///////////////////////////////////////////////////////////////////////
public class EllipticCurve extends aladdin.math.EllipticCurve<Vector, Field>
{
    // коэффициенты эллиптической кривой
    private final Field field; private final Vector a; private final Vector b;

    // конструктор
    public EllipticCurve(Field field, Vector a, Vector b)
    {
    	// сохранить переданные параметры
    	this.field = field; this.a = a; this.b = b;
    }
    // коэффициенты эллиптической кривой
    @Override public final Field  field() { return field; }
    @Override public final Vector a    () { return a;     }
    @Override public final Vector b    () { return b;     }

    ///////////////////////////////////////////////////////////////////////
    // Проверить принадлежность кривой
    ///////////////////////////////////////////////////////////////////////
    @Override public boolean isPoint(Point<Vector> P) 
    {
        // вычислить XY
        if (isZero(P)) return true; Vector xy = field.product(P.x(), P.y());
        
    	// вычислить Y^2 и X^2
		Vector y2 = field.sqr(P.y()); Vector x2 = field.sqr(P.x());
        
		// выполнить X^3 + aX^2
		Vector x3_ax2 = field.product(x2, field.add(P.x(), a)); 

		// сравнить Y^2 + YX и X^3 + aX^2 + b
		return field.add(y2, xy).equals(field.add(x3_ax2, b));
    }
    // вычислить дополнительный бит при сжатии
    @Override public int compress(Point<Vector> P)
    {
        // проверить корректность параметров
        if (isZero(P)) throw new IllegalArgumentException(); 
        
        // проверить на нулевую координату
        if (field.isZero(P.x())) return 0; 
        
        // вычислить YX^{-1}
        Vector product = field.product(P.y(), field.invert(P.x())); 
        
        // вычислить дополнительный бит
        return product.get(field.m() - 1); 
    }
    // вычислить точку кривой при расжатии
    @Override public Point<Vector> decompress(Vector x, int y0)
    {
        // для нулевой координаты x вычислить y = b^{2^{m-1}}
        if (field.isZero(x)) return new Point<Vector>(x, field.sqrt(b)); 
        
        // вычислить beta = x + a + bx^{-2}
        Vector beta = field.add(field.add(x, a), field.divide(b, field.sqr(x))); 
        
        // найти решение z уравнения z^2 + z = beta
        Vector z = field.quadratic_root(beta); 
        
        // проверить наличие корней
        if (z == null) throw new ArithmeticException(); 
        
        // при необходимости выбрать другой корень
        if (z.get(field.m() - 1) != y0) z = field.add(z, field.one()); 
        
        // вернуть точку эллиптической кривой
        return new Point<Vector>(x, field.product(x, z)); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Операции с точкой на эллиптической кривой
    ///////////////////////////////////////////////////////////////////////
    @Override public Point<Vector> add(Point<Vector> P, Point<Vector> Q)
    {
		// проверить на бесконечность
        if (isZero(Q)) return P; if (isZero(P)) return Q; 
        
		// выполнить сложение для частного случая
		if (P.x().equals(Q.x())) return (P.y().equals(Q.y())) ? twice(P) : zero();

        // вычислить deltaX = P.x + Q.x и deltaY = P.y + Q.y
		Vector deltaX = field.add(P.x(), Q.x());
		Vector deltaY = field.add(P.y(), Q.y());

		// вычислить gamma = deltaY / deltaX
		Vector gamma = field.divide(deltaY, deltaX);

		// вычислить x3 = gamma^2 + gamma + deltaX + a
		Vector x3 = field.add(a, field.add(deltaX, 
            field.add(field.sqr(gamma), gamma)
        ));
		// вычислить y3 = gamma * (P.x + x3) + x3 + P.y
		Vector y3 = field.add(P.y(), field.add(x3, 
            field.product(gamma, field.add(P.x(), x3))
        ));
		// вернуть результат сложения
		return new Point<Vector>(x3, y3);
    }
    // удвоение точки
    @Override public Point<Vector> twice(Point<Vector> P)
    {
        // проверить на бесконечность и нулевую точку 
		if (isZero(P)) return P; if (field.isZero(P.x())) return zero();
        
		// вычислить gamma = x + y / x
		Vector gamma = field.add(P.x(), field.divide(P.y(), P.x()));

		// вычислить x2 = gamma^2 + gamma + a 
		Vector x2 = field.add(a, field.add(gamma, field.sqr(gamma)));
        
		// вычислить y2 = x^2 + gamma x2 + x2
		Vector y2 = field.add(x2, field.add(
            field.product(gamma, x2), field.sqr(P.x())
        )); 
		// вернуть результат удвоения
		return new Point<Vector>(x2, y2);
    }
    // вычислить противоположную точку
    @Override public Point<Vector> negate(Point<Vector> P)
    {
        // вычислить противоположную точку
		return new Point<Vector>(P.x(), field.add(P.x(), P.y()));
    }
}