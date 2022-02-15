using System;

namespace Aladdin.CAPI.ANSI.Sign.DSA
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм подписи DSA
	///////////////////////////////////////////////////////////////////////////
	public class SignHash : CAPI.SignHash
	{
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

	    public override byte[] Sign(CAPI.IPrivateKey key, IRand rand, 
		    ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash)
	    {
		    // преобразовать тип ключа
		    X957.IPrivateKey privateKey = (X957.IPrivateKey)key; 
		
		    // преобразовать тип параметров
		    X957.IParameters parameters = (X957.IParameters)privateKey.Parameters;  

		    // определить параметры алгоритма
		    Math.BigInteger P = parameters.P; Math.BigInteger Q = parameters.Q; 
		    Math.BigInteger G = parameters.G; Math.BigInteger X = privateKey.X; 
  
		    // при необходимости укорачивания хэш-значения
		    int N = Q.BitLength; if (N < hash.Length * 8)
		    {
			    // выделить буфер для хэш-значения
			    byte[] buffer = new byte[(N + 7) / 8];
 
			    // скопировать хэш-значение
			    Array.Copy(hash, 0, buffer, 0, buffer.Length); hash = buffer; 
 
			    // обнулить неиспользуемые биты
			    hash[hash.Length - 1] &= (byte)~((1 << (8 - N % 8)) - 1); 
		    }
		    // преобразовать хэш-значение в число
		    Math.BigInteger Z = Math.Convert.ToBigInteger(hash, Endian); 

            // инициализировать переменные
            Math.BigInteger R = null; Math.BigInteger S = null;

           // вычислить верхнюю границу
	       Math.BigInteger max = Q - Math.BigInteger.One; 
            
            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do { 
                // сгенерировать случайное число
                Math.BigInteger K; do { K = new Math.BigInteger(N, random); }

                // проверить условие генерации
                while (K.CompareTo(max) >= 0); K = K + Math.BigInteger.One;

                // вычислить обратный элемент и выполнить вычисления
                Math.BigInteger K1 = K.ModInverse(Q); R = G.ModPow(K, P).Mod(Q);

	            // выполнить вычисления
	            S = ((Z + X * R).Mod(Q) * K1).Mod(Q);
            }
            // проверить ограничение
            while (R.Signum == 0 || S.Signum == 0); 

            // закодировать значение подписи
            ASN1.ANSI.X957.DssSigValue signature = 
                new ASN1.ANSI.X957.DssSigValue(
			        new ASN1.Integer(R), new ASN1.Integer(S)
            ); 
		    // вернуть значение подписи
		    return signature.Encoded; 
	    }
	}
}
    
