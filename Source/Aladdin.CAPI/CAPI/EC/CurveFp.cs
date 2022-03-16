using System; 
using System.IO; 

namespace Aladdin.CAPI.EC
{
    ////////////////////////////////////////////////////////////////////////////
    // Эллиптическая кривая над полем Fp
    ////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class CurveFp : Curve
    {
        // эллиптическая кривая
        private Math.Fp.EllipticCurve ec;
        
        // конструктор
        public CurveFp(Math.Fp.EllipticCurve ec, byte[] seed) 
          
            // сохранить переданные параметры
            : base(new FieldFp(ec.Field.P), ec.A, ec.B, seed) { this.ec = ec; }
         
        // конструктор
        public CurveFp(Math.BigInteger p, Math.BigInteger a, Math.BigInteger b, byte[] seed) 
          
            // сохранить переданные параметры
            : this(new FieldFp(p), a, b, seed) {}

        // конструктор
        public CurveFp(FieldFp field, Math.BigInteger a, Math.BigInteger b, byte[] seed) 
          
            // сохранить переданные параметры
            : base(field, a, b, seed) 
        { 
            // проверить корректность параметров
            if (a.Signum < 0 || b.Signum < 0) throw new ArgumentException();

            // проверить корректность параметров
            if (a.CompareTo(field.P) >= 0 || b.CompareTo(field.P) >= 0) 
            {
                // при ошибке выбросить исключение
                throw new ArgumentException();
            }
            // указать используемой поле
            Math.Fp.Field mathField = new Math.Fp.Field(field.P); 

            // создать эллиптическую кривую
            this.ec = new Math.Fp.EllipticCurve(mathField, a, b);
        } 
        ///////////////////////////////////////////////////////////////////////
        // Свойства эллиптической кривой
        ///////////////////////////////////////////////////////////////////////

        // конечное поле
        public new EC.FieldFp Field { get { return (EC.FieldFp)base.Field; }}
    
        // признак принадлежности эллиптической кривой
        public override bool IsPoint(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.BigInteger> mathPoint = GetMathPoint(P); 
        
            // проверить принадлежность точки
            return ec.IsPoint(mathPoint); 
        }
        // создать точку на эллиптической кривой
        protected override Point CreatePoint(Math.BigInteger x, Math.BigInteger y)
        {
            // создать точку на эллиптической кривой
            Math.Point<Math.BigInteger> mathPoint = new Math.Point<Math.BigInteger>(x, y); 
        
            // проверить принадлежность точки
            if (!ec.IsPoint(mathPoint)) throw new InvalidDataException(); 
        
            // вернуть созданную точку
            return new PointImpl<Math.BigInteger>(mathPoint, x, y); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////////
        public override Point Negate(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.BigInteger> mathPoint = GetMathPoint(P); 
        
            // вычислить противоположную точку
            mathPoint = ec.Negate(mathPoint); 
        
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.BigInteger>(
                mathPoint, mathPoint.X, mathPoint.Y
            ); 
        }
        public override Point Add(Point P, Point Q)
        {
            // извлечь математические точки
            Math.Point<Math.BigInteger> mathPointP = GetMathPoint(P); 
            Math.Point<Math.BigInteger> mathPointQ = GetMathPoint(Q); 
        
            // вычислить сумму точек
            Math.Point<Math.BigInteger> mathPoint = ec.Add(
                mathPointP, mathPointQ
            ); 
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.BigInteger>(
                mathPoint, mathPoint.X, mathPoint.Y
            ); 
        }
        public override Point Subtract(Point P, Point Q)
        {
            // извлечь математические точки
            Math.Point<Math.BigInteger> mathPointP = GetMathPoint(P); 
            Math.Point<Math.BigInteger> mathPointQ = GetMathPoint(Q); 
        
            // вычислить разность точек
            Math.Point<Math.BigInteger> mathPoint = ec.Subtract(
                mathPointP, mathPointQ
            ); 
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.BigInteger>(
                mathPoint, mathPoint.X, mathPoint.Y
            ); 
        }
        public override Point Twice(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.BigInteger> mathPoint = GetMathPoint(P); 
        
            // вычислить удвоенную точку
            mathPoint = ec.Twice(mathPoint); 

            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.BigInteger>(
                mathPoint, mathPoint.X, mathPoint.Y
            ); 
        }
        // вычисление кратного элемента
        public override Point Multiply(Point P, Math.BigInteger e)
        {
            // извлечь математическую точку
            Math.Point<Math.BigInteger> mathPoint = GetMathPoint(P); 
        
            // вычислить кратный элемент
            mathPoint = ec.Multiply(mathPoint, e); 

            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 

            // вернуть результат
            return new PointImpl<Math.BigInteger>(
                mathPoint, mathPoint.X, mathPoint.Y
            ); 
        }
        // сумма кратных элементов
        public override Point MultiplySum(
            Point P, Math.BigInteger a, Point Q, Math.BigInteger b)
        {
            // извлечь математические точки
            Math.Point<Math.BigInteger> mathPointP = GetMathPoint(P); 
            Math.Point<Math.BigInteger> mathPointQ = GetMathPoint(Q); 
        
            // вычислить сумму кратных элементов
            Math.Point<Math.BigInteger> mathPoint = ec.MultiplySum(
                mathPointP, a, mathPointQ, b
            ); 
            // проверить на бесконечную точку
            if (ec.IsZero(mathPoint)) return Zero; 
        
            // вернуть результат
            return new PointImpl<Math.BigInteger>(
                mathPoint, mathPoint.X, mathPoint.Y
            ); 
        }
        // извлечь математическую точку
        private Math.Point<Math.BigInteger> GetMathPoint(Point P)
        {
            // проверить на бесконечную точку
            if (IsZero(P)) return ec.Zero; 
        
            // в зависимости от типа
            if (P is PointImpl<Math.BigInteger>) 
            {
                // извлечь математическую точку
                return ((PointImpl<Math.BigInteger>)P).MathPoint; 
            }
            // создать математическую точку
            return new Math.Point<Math.BigInteger>(P.X, P.Y); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование точек эллиптической кривой
        ///////////////////////////////////////////////////////////////////////////
    
        // вычислить дополнительный бит при сжатии
        protected override int Compress(Point P)
        {
            // извлечь математическую точку
            Math.Point<Math.BigInteger> mathPoint = GetMathPoint(P); 
        
            // вычислить дополнительный бит при сжатии
            return ec.Compress(mathPoint); 
        }
        // вычислить точку кривой при расжатии
        protected override Point Decompress(Math.BigInteger x, int y0)
        {
            try { 
                // вычислить точку кривой при расжатии
                Math.Point<Math.BigInteger> mathPoint = ec.Decompress(x, y0); 

                // проверить на бесконечную точку
                if (ec.IsZero(mathPoint)) return Zero; 
            
                // выполнить преобразование типа
                return new PointImpl<Math.BigInteger>(
                    mathPoint, mathPoint.X, mathPoint.Y
                ); 
            }
            // обработать возможное исключение
            catch (ArithmeticException) { throw new InvalidDataException(); }
        }
    }
}