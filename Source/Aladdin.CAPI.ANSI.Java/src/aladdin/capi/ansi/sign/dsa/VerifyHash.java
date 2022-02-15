package aladdin.capi.ansi.sign.dsa;
import aladdin.math.*;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.ansi.x957.*;
import java.security.*;
import java.math.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи DSA
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.VerifyHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    @Override public void verify(aladdin.capi.IPublicKey key, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash, 
        byte[] signature) throws IOException, SignatureException
    {
        // раскодировать значение подписи
        DssSigValue encoded = new DssSigValue(Encodable.decode(signature)); 

        // раскодировать значения R и S
        BigInteger R = encoded.r().value(); BigInteger S = encoded.s().value(); 

        // получить параметры алгоритма
        aladdin.capi.ansi.x957.IParameters parameters = 
            (aladdin.capi.ansi.x957.IParameters)key.parameters(); 

        // преобразовать тип ключа
        aladdin.capi.ansi.x957.IPublicKey publicKey = 
            (aladdin.capi.ansi.x957.IPublicKey)key;

        // извлечь параметры алгоритма
        BigInteger P  = parameters.getP(); BigInteger Q = parameters.getQ();
        BigInteger G  = parameters.getG(); BigInteger Y = publicKey .getY();

        // проверить корректность R
        if (R.signum() == 0 || R.compareTo(Q) >= 0) 
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
        // проверить корректность S
        if (S.signum() == 0 || S.compareTo(Q) >= 0)
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
        // при необходимости укорачивания хэш-значения
        int N = Q.bitLength(); if (N < hash.length * 8)
        {
            // выделить буфер для хэш-значения
            byte[] buffer = new byte[(N + 7) / 8];

            // скопировать хэш-значение
            System.arraycopy(hash, 0, buffer, 0, buffer.length); hash = buffer; 

            // обнулить неиспользуемые биты
            hash[hash.length - 1] &= (byte)~((1 << (8 - N % 8)) - 1); 
        }
        // преобразовать хэш-значение в число
        BigInteger Z = Convert.toBigInteger(hash, ENDIAN); 

        // выполнить вычисления
        BigInteger W = S.modInverse(Q); 

        // вычислить вычисления
        BigInteger GU1 = G.modPow(Z.multiply(W).mod(Q), P);
        BigInteger YU2 = Y.modPow(R.multiply(W).mod(Q), P);

        // проверить корректность подписи
        if (!GU1.multiply(YU2).mod(P).mod(Q).equals(R))
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
    }
}
