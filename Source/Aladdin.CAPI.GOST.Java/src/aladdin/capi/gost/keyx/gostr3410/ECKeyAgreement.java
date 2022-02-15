package aladdin.capi.gost.keyx.gostr3410;
import aladdin.capi.gost.gostr3410.*; 
import aladdin.*; 
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import aladdin.capi.derive.*; 
import java.security.*; 
import java.security.spec.*; 
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа ГОСТ Р 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////////
public abstract class ECKeyAgreement extends KeyAgreement
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // алгоритм наследования ключа
    private final KeyDerive keyDerive; 
    
    // конструктор
    protected ECKeyAgreement(KeyDerive keyDerive)
    {
        // сохранить переданные параметры
        this.keyDerive = RefObject.addRef(keyDerive); 
    }
    // конструктор
    protected ECKeyAgreement() 
    { 
        // сохранить переданные параметры
        this.keyDerive = new NOKDF(ENDIAN); 
    } 
    // деструктор
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
        RefObject.release(keyDerive); super.onClose();
    }
    // размер случайных данных
    protected int randomSize() { return 8; }
    
    // создать алгоритм хэширования
    protected abstract Hash createHashAlgorithm(
        IPrivateKey privateKey, int keySize) throws IOException; 
    
    // сгенерировать случайные данные
    @Override public byte[] generate(aladdin.capi.IParameters parameters, IRand rand) throws IOException 
    {
        // сгенерировать случайные данные
        byte[] random = new byte[randomSize()]; rand.generate(random, 0, random.length);
        
        // для случайных данных
        boolean zero = true; for (int i = 0; i < random.length; i++)
        {
            // проверить отсутствие нулевых данных
            if (random[i] != 0) { zero = false; break; }
        }
        // скорректировать нулевые данные
        if (zero) random[0] = 0x1; return random;  
    }
    // наследовать ключ
    @Override public ISecretKey deriveKey(aladdin.capi.IPrivateKey privateKey, 
        aladdin.capi.IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException 
    {
        // преобразовать тип параметров
        IECParameters parameters = (IECParameters) privateKey.parameters(); 

        // преобразовать тип данных
        IECPrivateKey privateKeyX = (IECPrivateKey)privateKey; 
        IECPublicKey  publicKeyX  = (IECPublicKey )publicKey;

        // извлечь параметры алгоритма
        Curve ec = parameters.getCurve(); BigInteger q = parameters.getOrder();

        // создать большое число по случайным данным
        BigInteger ukm = Convert.toBigInteger(random, ENDIAN); 

        // создать точку эллиптической кривой
        ECPoint Q = publicKeyX.getW();
        
        // выполнить математические операции
        ECPoint point = ec.multiply(Q, privateKeyX.getS().multiply(ukm).mod(q));
        
        // выделить память для точки эллиптической кривой
        byte[] xy = new byte[(q.bitLength() + 7) / 8 * 2];  
            
        // закодировать координаты точки
        Convert.fromBigInteger(point.getAffineX(), ENDIAN, xy,             0, xy.length / 2); 
        Convert.fromBigInteger(point.getAffineY(), ENDIAN, xy, xy.length / 2, xy.length / 2); 

        // создать алгоритм хэширования
        try (Hash hashAlgorithm = createHashAlgorithm(privateKey, keySize))
        {
            // получить ключ как хэш-значение
            try (ISecretKey key = keyDerive.keyFactory().create(hashAlgorithm.hashData(xy, 0, xy.length)))
            {
                // выполнить наследование ключа
                return keyDerive.deriveKey(key, random, keyFactory, keySize); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
    }
}
