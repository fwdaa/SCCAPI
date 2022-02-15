using System;

namespace Aladdin.CAPI.ANSI.Sign.DSA
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм проверки подписи DSA
	///////////////////////////////////////////////////////////////////////////
	public class VerifyHash : CAPI.VerifyHash
	{
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

	    public override void Verify(CAPI.IPublicKey key, 
		    ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash, byte[] signature)
	    {
		    // раскодировать значение подписи
		    ASN1.ANSI.X957.DssSigValue encoded = 
			    new ASN1.ANSI.X957.DssSigValue(ASN1.Encodable.Decode(signature)); 

		    // раскодировать значения R и S
		    Math.BigInteger R = encoded.R.Value; Math.BigInteger S = encoded.S.Value; 

		    // преобразовать тип ключа
		    ANSI.X957.IPublicKey publicKey = (ANSI.X957.IPublicKey)key;

		    // получить параметры алгоритма
		    ANSI.X957.IParameters parameters = (ANSI.X957.IParameters)publicKey.Parameters; 

		    // извлечь параметры алгоритма
		    Math.BigInteger P  = parameters.P; Math.BigInteger Q = parameters.Q;
		    Math.BigInteger G  = parameters.G; Math.BigInteger Y = publicKey .Y;

		    // проверить корректность R
		    if (R.Signum == 0 || R.CompareTo(Q) >= 0)
            {
                // при ошибке выбросить исключение
                throw new SignatureException(); 
            }
		    // проверить корректность S
		    if (S.Signum == 0 || S.CompareTo(Q) >= 0)
            {
                // при ошибке выбросить исключение
                throw new SignatureException(); 
            }
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

		    // выполнить вычисления
		    Math.BigInteger W = S.ModInverse(Q); 

		    // вычислить вычисления
		    Math.BigInteger GU1 = G.ModPow((Z * W).Mod(Q), P);
		    Math.BigInteger YU2 = Y.ModPow((R * W).Mod(Q), P);

		    // проверить корректность подписи
		    if ((GU1 * YU2).Mod(P).Mod(Q) != R) throw new SignatureException(); 
	    }
	}
}
