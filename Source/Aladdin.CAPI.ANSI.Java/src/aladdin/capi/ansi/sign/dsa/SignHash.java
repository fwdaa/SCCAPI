package aladdin.capi.ansi.sign.dsa;
import aladdin.math.*;
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.ansi.x957.*;
import aladdin.capi.*; 
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи DSA
///////////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.SignHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    @Override public byte[] sign(aladdin.capi.IPrivateKey key, 
        IRand rand, AlgorithmIdentifier hashAlgorithm, byte[] hash) throws IOException
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.x957.IPrivateKey privateKey = 
            (aladdin.capi.ansi.x957.IPrivateKey)key; 

        // преобразовать тип параметров
        aladdin.capi.ansi.x957.IParameters parameters = 
            (aladdin.capi.ansi.x957.IParameters)privateKey.parameters();  

        // определить параметры алгоритма
        BigInteger P = parameters.getP(); BigInteger Q = parameters.getQ(); 
        BigInteger G = parameters.getG(); BigInteger X = privateKey.getX(); 

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
        
        // указать начальные условия
        BigInteger R = BigInteger.ZERO; BigInteger S = BigInteger.ZERO;

        // указать генератор случайных чисел
        try (Random random = new Random(rand)) 
        {
            // вычислить верхнюю границу
            BigInteger max = Q.subtract(BigInteger.ONE); 
            
            // проверить ограничение
            for (BigInteger K; R.signum() == 0 || S.signum() == 0; ) 
            {
                // сгенерировать случайное число
                do { K = new BigInteger(N, random); }

                // проверить условие генерации
                while (K.compareTo(max) >= 0); K = K.add(BigInteger.ONE);

                // вычислить обратный элемент
                BigInteger K1 = K.modInverse(Q); R = G.modPow(K, P).mod(Q);

                // выполнить вычисления
                S = Z.add(X.multiply(R)).mod(Q).multiply(K1).mod(Q);
            }
        }
        // вернуть значение подписи
        return new DssSigValue(new Integer(R), new Integer(S)).encoded(); 
    }
}
