package aladdin.capi.stb.sign.stb11762;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.math.Fp.*;
import aladdin.capi.*;
import aladdin.capi.stb.stb11762.*;
import java.io.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм выработки подписи данных СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class SignData extends aladdin.capi.SignData
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // алгоритм хэширования и секретный параметр
    private Hash hashAlgorithm;	private BigInteger K;
    
    // конструктор
    public SignData() { hashAlgorithm = null; K = null; }
    
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); super.onClose(); 
    }
    // инициализировать алгоритм
    @Override public void init(IPrivateKey privateKey, IRand rand) throws IOException 
    { 
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 
        
        // преобразовать тип параметров
        IBDSParameters parameters = (IBDSParameters)privateKey.parameters(); 
        
        // прочитать параметры алгоритма
        BigInteger P = parameters.bdsP(); BigInteger Q = parameters.bdsQ();
        BigInteger A = parameters.bdsA(); int        R = parameters.bdsR();
        
        // выполнить базовую функцию
        super.init(privateKey, rand); K = BigInteger.ZERO; 

        // указать генератор случайных чисел
        try (Random random = new Random(rand)) 
        {
            // до выполнения требуемых условий
            while (K.signum() == 0 || K.compareTo(Q) >= 0)
            {
                // сгенерировать число 0 < K < Q
                K = new BigInteger(R, random);
            }
        }
        // вычислить T = A^(K)
        BigInteger T = (new MontGroup(P)).power(A, K);

        // закодировать число T
        byte[] encodedT = Convert.fromBigInteger(T, ENDIAN);  

        // создать алгоритм хэширования
        hashAlgorithm = createHashAlgorithm(privateKey, parameters.bdsH()); 

        // прохэшировать число T
        hashAlgorithm.init(); hashAlgorithm.update(encodedT, 0, encodedT.length); 
    }
    // обработать данные
    @Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
    {
        // прохэшировать данные
        hashAlgorithm.update(data, dataOff, dataLen); 
    }
    // получить подпись данных
    @Override public byte[] finish(IRand rand) throws IOException
    {
        // преобразовать тип ключа
        IBDSPrivateKey stbPrivateKey = (IBDSPrivateKey)privateKey(); 
        
        // преобразовать тип параметров
        IBDSParameters parameters = (IBDSParameters)stbPrivateKey.parameters(); 
        
        // прочитать параметры алгоритма
        BigInteger Q = parameters.bdsQ(); int R = parameters.bdsR();

        // получить хэш-значение
        byte[] H = new byte[32]; hashAlgorithm.finish(H, 0);
        
        // обнулить незначащие биты
        if (((R - 1) % 8) != 0) H[(R - 1) / 8] &= (byte)((1 << ((R - 1) % 8)) - 1);

        // преобразовать хэш-значение в число U
        BigInteger U = Convert.toBigInteger(H, 0, (R + 6) / 8, ENDIAN);

        // выполнить вычисления
        BigInteger XU = stbPrivateKey.bdsX().multiply(U).mod(Q);

        // вычислить число V
        BigInteger V = (K.compareTo(XU) > 0) ? K.subtract(XU) : K.add(Q).subtract(XU);

        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 

        // проверить корректность
        if (U.signum() == 0 || V.signum() == 0) throw new IllegalStateException(); 

        // выполнить конкатенацию 
        BigInteger UV = U.shiftLeft(R).add(V); 

        // вычислить подпись
        byte[] signature = Convert.fromBigInteger(UV, ENDIAN, (R + 3) / 4); 
        
        // вернуть вычисленную подпись
        super.finish(rand); return signature; 
    }
    // создать алгоритм хэширования
    protected Hash createHashAlgorithm(IPrivateKey privateKey, byte[] start) throws IOException
    { 
        // создать алгоритм хэширования
        return new aladdin.capi.stb.hash.STB11761(start);     
    }
}
