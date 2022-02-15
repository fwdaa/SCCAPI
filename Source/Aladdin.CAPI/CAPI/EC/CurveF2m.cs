using System; 
using System.IO; 

namespace Aladdin.CAPI.EC
{
    ////////////////////////////////////////////////////////////////////////////
    // Эллиптическая кривая над полем F2m
    ////////////////////////////////////////////////////////////////////////////
    public class CurveF2m : Curve
    {
        // эллиптическая кривая
        private Math.F2m.EllipticCurve ec; 
    
        // конструктор
        public CurveF2m(Math.F2m.EllipticCurve ec, byte[] seed) 
          
            // сохранить переданные параметры
            : base(new FieldF2m(ec.Field), ec.A.ToBigInteger(), ec.B.ToBigInteger(), seed) { this.ec = ec; }
         
        // конструктор
        public CurveF2m(FieldF2m field, Math.BigInteger a, Math.BigInteger b, byte[] seed) 
          
            // сохранить переданные параметры
            : base(field, a, b, seed) 
        { 
            // проверить корректность параметров
            if (a.BitLength > field.M || b.BitLength > field.M) throw new ArgumentException();

            // преобразовать тип коэффициентов
            Math.Vector vectorA = new Math.Vector(a, field.M); 
            Math.Vector vectorB = new Math.Vector(b, field.M); 

            // в зависимости от типа поля
            if (field.ReductionPolynomial == null)
            {
                // указать используемой поле
                Math.F2m.Field mathField = new Math.F2m.NormField(field.M); 

                // создать эллиптическую кривую
                ec = new Math.F2m.EllipticCurve(mathField, vectorA, vectorB);
            }
            else {
                // преобразовать тип образующего многочлена
                Math.Polynom polynom = new Math.Polynom(field.ReductionPolynomial); 

                // указать используемой поле
                Math.F2m.Field mathField = new Math.F2m.PolyField(polynom); 

                // создать эллиптическую кривую
                ec = new Math.F2m.EllipticCurve(mathField, vectorA, vectorB);
            }
        } 
        ///////////////////////////////////////////////////////////////////////
        // Свойства эллиптической кривой
        ///////////////////////////////////////////////////////////////////////

        // конечное поле
        public new EC.FieldF2m Field { get { return (EC.FieldF2m)base.Field; }}
    
        // признак принадлежности эллиптической кривой
        public override bool IsPoint(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.Vector> mathPoint = GetMathPoint(P); 
        
            // проверить принадлежность точки
            return ec.IsPoint(mathPoint); 
        }
        // создать точку на эллиптической кривой
        protected override Point CreatePoint(Math.BigInteger x, Math.BigInteger y) 
        {
            // создать точку на эллиптической кривой
            Math.Point<Math.Vector> mathPoint = new Math.Point<Math.Vector>(
                new Math.Vector(x, Field.M), 
                new Math.Vector(y, Field.M) 
            ); 
            // проверить принадлежность точки
            if (!ec.IsPoint(mathPoint)) throw new InvalidDataException(); 
        
            // вернуть созданную точку
            return new PointImpl<Math.Vector>(mathPoint, x, y); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////////
        public override Point Negate(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.Vector> mathPoint = GetMathPoint(P); 
        
            // вычислить противоположную точку
            mathPoint = ec.Negate(mathPoint); 
        
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.Vector>(mathPoint, 
                mathPoint.X.ToBigInteger(), mathPoint.Y.ToBigInteger()
            ); 
        }
        public override Point Add(Point P, Point Q)
        {
            // извлечь математические точки
            Math.Point<Math.Vector> mathPointP = GetMathPoint(P); 
            Math.Point<Math.Vector> mathPointQ = GetMathPoint(Q); 
        
            // вычислить сумму точек
            Math.Point<Math.Vector> mathPoint = ec.Add(
                mathPointP, mathPointQ
            ); 
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.Vector>(mathPoint, 
                mathPoint.X.ToBigInteger(), mathPoint.Y.ToBigInteger()
            ); 
        }
        public override Point Subtract(Point P, Point Q)
        {
            // извлечь математические точки
            Math.Point<Math.Vector> mathPointP = GetMathPoint(P); 
            Math.Point<Math.Vector> mathPointQ = GetMathPoint(Q); 
        
            // вычислить разность точек
            Math.Point<Math.Vector> mathPoint = ec.Subtract(
                mathPointP, mathPointQ
            ); 
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.Vector>(mathPoint, 
                mathPoint.X.ToBigInteger(), mathPoint.Y.ToBigInteger()
            ); 
        }
        public override Point Twice(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.Vector> mathPoint = GetMathPoint(P); 
        
            // вычислить удвоенную точку
            mathPoint = ec.Twice(mathPoint); 

            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.Vector>(mathPoint, 
                mathPoint.X.ToBigInteger(), mathPoint.Y.ToBigInteger()
            ); 
        }
        // вычисление кратного элемента
        public override Point Multiply(Point P, Math.BigInteger e)
        {
            // извлечь математическую точку
            Math.Point<Math.Vector> mathPoint = GetMathPoint(P); 
        
            // вычислить кратный элемент
            mathPoint = ec.Multiply(mathPoint, e); 

            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.Vector>(mathPoint, 
                mathPoint.X.ToBigInteger(), mathPoint.Y.ToBigInteger()
            ); 
        }
        // сумма кратных элементов
        public override Point MultiplySum(
            Point P, Math.BigInteger a, Point Q, Math.BigInteger b)
        {
            // извлечь математические точки
            Math.Point<Math.Vector> mathPointP = GetMathPoint(P); 
            Math.Point<Math.Vector> mathPointQ = GetMathPoint(Q); 
        
            // вычислить сумму кратных элементов
            Math.Point<Math.Vector> mathPoint = ec.MultiplySum(
                mathPointP, a, mathPointQ, b
            ); 
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.Vector>(mathPoint, 
                mathPoint.X.ToBigInteger(), mathPoint.Y.ToBigInteger()
            ); 
        }
        // извлечь математическую точку
        private Math.Point<Math.Vector> GetMathPoint(Point P)
        {
            // проверить на бесконечную точку
            if (IsZero(P)) return ec.Zero; 
        
            // в зависимости от типа
            if (P is PointImpl<Math.Vector>) 
            {
                // извлечь математическую точку
                return ((PointImpl<Math.Vector>)P).MathPoint; 
            }
            try { 
                // создать математическую точку
                return new Math.Point<Math.Vector>(
                    new Math.Vector(P.X, Field.M), 
                    new Math.Vector(P.Y, Field.M) 
                ); 
            }
            // обработать возможное исключение
            catch (IOException) { throw new ArithmeticException(); }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование точек эллиптической кривой
        ///////////////////////////////////////////////////////////////////////////
    
        // вычислить дополнительный бит при сжатии
        protected override int Compress(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.Vector> mathPoint = GetMathPoint(P); 
        
            // вычислить дополнительный бит при сжатии
            return ec.Compress(mathPoint); 
        }
        // вычислить точку кривой при расжатии
        protected override Point Decompress(Math.BigInteger x, int y0)
        {
            // выполнить преобразование типа
            Math.Vector vectorX = new Math.Vector(x, Field.FieldSize); 
            try { 
                // вычислить точку кривой при расжатии
                Math.Point<Math.Vector> mathPoint = ec.Decompress(vectorX, y0); 

                // проверить на бесконечную точку
                if (ec.IsZero(mathPoint)) return Zero; 
        
                // выполнить преобразование типа
                return new PointImpl<Math.Vector>(mathPoint, 
                    mathPoint.X.ToBigInteger(), mathPoint.Y.ToBigInteger()
                ); 
            }
            // обработать возможное исключение
            catch (ArithmeticException) { throw new InvalidDataException(); }
        }
    }
}

