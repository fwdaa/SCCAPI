package aladdin.capi.derive;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Схема диверсификации KDF_TREE
///////////////////////////////////////////////////////////////////////////
public class TREEKDF extends KeyDerive
{
    // алгоритм выработки МАС и размер MAC-значения
    private final Mac algorithm; private final int macSize; 

    // параметры алгоритма
    private final byte[] label; private final int R; 

    // конструктор
    public TREEKDF(Mac algorithm, byte[] label, int R)
    {
        // проверить корректность параметров
        if (R <= 0 || R > 4) throw new IllegalArgumentException(); 

        // сохранить переданные параметры
        this.algorithm = RefObject.addRef(algorithm); 

        // сохранить переданные параметры
        macSize = algorithm.macSize(); this.label = label; this.R = R; 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(algorithm); super.onClose();
    } 
    // используемый алгоритм имитовставки
    public final Mac macAlgorithm() { return algorithm; }
    
    // тип ключа
    @Override public SecretKeyFactory keyFactory() { return algorithm.keyFactory(); } 
    
	// сгенерировать блок данных
	@Override public ISecretKey deriveKey(ISecretKey key, byte[] seed, 
        SecretKeyFactory keyFactory, int deriveSize) 
        throws IOException, InvalidKeyException
    {
        // проверить наличие размера
        if (deriveSize < 0) throw new IllegalStateException(); 
        
        // определить число итераций
        int iterations = (deriveSize + macSize - 1) / macSize; long l = deriveSize * 8; 

        // проверить корректность данных
        if (iterations > (1 << (R * 8)) - 1) throw new IllegalArgumentException(); 

        // определить число байтов для L
        int L = (l <= 0xFF) ? 1 : ((l <= 0xFFFF) ? 2 : ((l <= 0xFFFFFF) ? 3 : 4));  

        // выделить буфер требуемого размера
        byte[] buffer = new byte[deriveSize]; int offset = 0;  
        
        // для всех блоков данных
        for (int i = 1; deriveSize > 0; offset += macSize, deriveSize -= macSize, i++)
        {
            // выделить буфер требуемого размера
            byte[] data = new byte[R + label.length + 1 + seed.length + L]; 

            // закодировать номер итерации
            for (int j = 0; j < R; j++) data[R - j - 1] = (byte)(i >>> (8 * j));

            // скопировать label и seed
            System.arraycopy(label, 0, data, R                   , label.length); 
            System.arraycopy(seed , 0, data, R + label.length + 1, seed .length); 

            // указать смещения числа битов
            int offsetL = R + label.length + 1 + seed.length;

            // закодировать число битов
            for (int j = 0; j < L; j++) data[offsetL + L - j - 1] = (byte)(l >>> (8 * j));

            // выполнить хэширование данных
            byte[] mac = algorithm.macData(key, data, 0, data.length); 

            // скопировать хэш-значение
            System.arraycopy(mac, 0, buffer, offset, (mac.length < deriveSize) ? mac.length : deriveSize); 
        } 
        // вернуть созданный ключ
        return keyFactory.create(buffer); 
    } 
}
