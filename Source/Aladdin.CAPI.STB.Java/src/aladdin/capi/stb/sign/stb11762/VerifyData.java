package aladdin.capi.stb.sign.stb11762;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.math.Fp.*;
import aladdin.capi.*;
import aladdin.capi.stb.stb11762.*;
import aladdin.util.*;
import java.security.*;
import java.io.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи данных СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class VerifyData extends aladdin.capi.VerifyData
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // алгоритм хэширования и хэш-значение
    private Hash hashAlgorithm; private byte[] hash;          
    
    // конструктор
    public VerifyData() { hashAlgorithm = null; hash = null; }
    
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); super.onClose();
    }
    // инициализировать алгоритм
    @Override public void init(IPublicKey publicKey, 
        byte[] signature) throws IOException, SignatureException
    { 
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null;
            
        // преобразовать тип ключа
        IBDSPublicKey stbPublicKey = (IBDSPublicKey)publicKey; 

        // преобразовать тип параметров
        IBDSParameters parameters = (IBDSParameters)publicKey.parameters(); 

        // прочитать параметры алгоритма
        BigInteger P = parameters.bdsP(); BigInteger A = parameters.bdsA(); 
        
        // вызвать базовую функцию
        super.init(publicKey, signature); int R = parameters.bdsR();

        // раскодировать значение подписи
        BigInteger UV = Convert.toBigInteger(signature, ENDIAN); 
            
        // извлечь параметр U
        BigInteger U = UV.shiftRight(R);

        // вычислить параметр V
        BigInteger V = UV.subtract(U.shiftLeft(R)); 

        // проверить корректность U и V
        if (U.signum() == 0 || V.signum() == 0 || V.bitLength() > R) 
        {
            // при ошибке выбросить исключение
            throw new SignatureException();
        }
        // извлечь хэш-значение
        hash = Convert.fromBigInteger(U, ENDIAN, (R + 6) / 8);
            
        // вычислить T = A^(V) * Y^(U)
        BigInteger T = new MontGroup(P).power_product(A, V, stbPublicKey.bdsY(), U);

        // закодировать число T
        byte[] encodedT = Convert.fromBigInteger(T, ENDIAN);

        // создать алгоритм хэширования
        hashAlgorithm = createHashAlgorithm(publicKey, parameters.bdsH()); 

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
    @Override public void finish() throws IOException, SignatureException
    {
        // преобразовать тип параметров
        IBDSParameters parameters = (IBDSParameters)publicKey().parameters(); 
        
        // прочитать параметры алгоритма
        byte[] H = new byte[32]; int R = parameters.bdsR(); 

        // получить хэш-значение
        hashAlgorithm.finish(H, 0); if (((R - 1) % 8) != 0)
        {
            // обнулить незначащие биты
            H[(R - 1) / 8] &= (byte)((1 << ((R - 1) % 8)) - 1);
        }
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 
           
        // проверить совпадение хэш-значений
        if (!Array.equals(hash, 0, H, 0, (R + 6) / 8))
        {
            // при ошибке выбросить исключение
            throw new SignatureException(); 
        }
    }
    // создать алгоритм хэширования
    protected Hash createHashAlgorithm(
        IPublicKey publicKey, byte[] start) throws IOException 
    { 
        // создать алгоритм хэширования
        return new aladdin.capi.stb.hash.STB11761(start); 
    }
}
