package aladdin.capi.stb.keyx.stb11762;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.math.Fp.*;
import aladdin.capi.*;
import aladdin.capi.stb.stb11762.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа
///////////////////////////////////////////////////////////////////////////
public class KeyAgreement extends RefObject implements IKeyAgreement
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
        
    // наследовать ключ на стороне оправителе
    @Override public DeriveData deriveKey(IPrivateKey privateKey, 
        IPublicKey publicKey, IRand rand, 
        SecretKeyFactory keyFactory, int keySize) throws IOException 
    {
        // преобразовать тип параметров
        IBDHParameters bdhParameters = (IBDHParameters)publicKey.parameters(); 

        // открытый ключ
        IBDHPublicKey bdhPublicKey = (IBDHPublicKey)publicKey; 

        // извлечь параметры алгоритма
        int N = bdhParameters.bdhN(); BigInteger P = bdhParameters.bdhP();
        int R = bdhParameters.bdhR(); BigInteger G = bdhParameters.bdhG(); 
        
        // извлечь параметр Y
        BigInteger Y = bdhPublicKey.bdhY(); BigInteger K; 

        // указать генератор случайных чисел
        try (Random random = new Random(rand)) 
        {
            // сгенерировать случайное число K
            K = new BigInteger(R, random); 
        }
        // указать группу Монтгомери
        MulGroup<BigInteger> group = new MontGroup(P); 

        // вычислить U = Y^(K) (mod P) и V = G^(K) (mod P)
        BigInteger U = group.power(Y, K); BigInteger V = group.power(G, K);

        // получить закодированные значения U и V
        byte[] encodedU = Convert.fromBigInteger(U, ENDIAN);  
        byte[] encodedV = Convert.fromBigInteger(V, ENDIAN);  

        // выделить память для ключа
        byte[] key = new byte[(N + 7) / 8]; 
            
        // в зависимости от размера ключа
        if (key.length > encodedU.length)
        {
            // скопировать значение ключа
            System.arraycopy(encodedU, 0, key, 0, encodedU.length);
                
            // обнулить неиспользуемые данные
            for (int i = encodedU.length; i < key.length; i++) key[i] = 0; 
        }
        else {
            // скопировать значение ключа
            System.arraycopy(encodedU, 0, key, 0, key.length);

            // выделить нужное число бит
            if ((N % 8) > 0) key[N / 8] &= (byte)((1 << (N % 8)) - 1); 
        }
        // вернуть значение ключа и нонки
        try (ISecretKey k = keyFactory.create(key)) { return new DeriveData(k, encodedV); }
    }
    // наследовать ключ на стороне получателе
    @Override public ISecretKey deriveKey(IPrivateKey privateKey, 
        IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
    {
        // преобразовать тип личного ключа
        IBDHPrivateKey bdhPrivateKey = (IBDHPrivateKey)privateKey;
            
        // преобразовать тип параметров
        IBDHParameters bdhParameters = (IBDHParameters)privateKey.parameters(); 

        // извлечь параметры алгоритма
        int N = bdhParameters.bdhN(); BigInteger P = bdhParameters.bdhP();

        // прочитать большое число V
        BigInteger V = Convert.toBigInteger(random, ENDIAN); 
            
        // вычислить V^(X) (mod P)
        BigInteger U = (new MontGroup(P)).power(V, bdhPrivateKey.bdhX());

        // получить закодированное значение ключа
        byte[] encodedU = Convert.fromBigInteger(U, ENDIAN);  

        // выделить память для ключа
        byte[] key = new byte[(N + 7) / 8]; 
            
        // в зависимости от размера ключа
        if (key.length > encodedU.length)
        {
            // скопировать значение ключа
            System.arraycopy(encodedU, 0, key, 0, encodedU.length);
                
            // обнулить неиспользуемые данные
            for (int i = encodedU.length; i < key.length; i++) key[i] = 0; 
        }
        else {
            // скопировать значение ключа
            System.arraycopy(encodedU, 0, key, 0, key.length);

            // выделить нужное число бит
            if ((N % 8) > 0) key[N / 8] &= (byte)((1 << (N % 8)) - 1); 
        }
        // вернуть созданные ключ
        return keyFactory.create(key); 
    }
}
