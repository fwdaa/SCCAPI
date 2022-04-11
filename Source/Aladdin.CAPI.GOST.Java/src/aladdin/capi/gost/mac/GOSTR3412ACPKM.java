package aladdin.capi.gost.mac;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.capi.mac.*; 
import aladdin.capi.gost.keys.*; 
import aladdin.capi.gost.derive.*; 
import aladdin.capi.gost.mode.gostr3412.*; 
import java.io.*; 
import java.security.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки OMAC
///////////////////////////////////////////////////////////////////////////
public class GOSTR3412ACPKM extends OMAC1
{
    // алгоритм смены ключей и размер ключа
    private final MasterACPKM masterACPKM; private int keySize; 

    // создать алгоритм вычисления имитовставки OMAC
    public static GOSTR3412ACPKM create(Cipher cipher, int N, int T, int macSize) throws IOException 
    {
        // создать алгоритм смены ключа для OMAC-ACPKM
        try (MasterACPKM masterACPKM = new MasterACPKM(cipher, T))
        {
            // указать параметры режима
            CipherMode.CBC parameters = new CipherMode.CBC(
                new byte[cipher.blockSize()]
            ); 
            // создать режим CBC со специальной сменой ключа
            try (Cipher modeCBC = new CBC(cipher, parameters, masterACPKM, N))
            {
                // создать алгоритм вычисления имитовставки OMAC
                return new GOSTR3412ACPKM(modeCBC, masterACPKM, macSize); 
            }
        }
    }
    // конструктор
    private GOSTR3412ACPKM(Cipher modeCBC, MasterACPKM masterACPKM, int macSize) 
    {
        // сохранить переданные параметры
        super(modeCBC, macSize); this.masterACPKM = RefObject.addRef(masterACPKM); 
    }
    // освободить ресурсы
    @Override protected void onClose() throws IOException    
    { 
        // освободить ресурсы
        RefObject.release(masterACPKM); super.onClose();
    }
    // инициализировать алгоритм
    @Override public void init(ISecretKey key) throws IOException, InvalidKeyException
    {
        // инициализировать алгоритм
        masterACPKM.init(key); keySize = key.length(); 

        // создать новый ключ
        try (ISecretKey newKey = masterACPKM.deriveKey(
            null, null, GOST.INSTANCE, keySize))
        {
            // инициализировать алгоритм
            super.init(newKey);
        }
    }
    // завершить преобразование
    @Override protected void finish(byte[] data, int dataOff, 
        int dataLen, byte[] mac, int macOff) throws IOException
    {
        // завершить преобразование 
        super.finish(data, dataOff, dataLen, mac, macOff); 

        // освободить ресурсы
        masterACPKM.finish(); 
    }
    // получить дополнительный ключ
    @Override protected byte[] getXorK1() 
    { 
        // создать дополнительный ключ
        return masterACPKM.getXorK1(keySize); 
    }
    // создать дополнительный ключ
    @Override protected byte[] createXorK1(ISecretKey key) { return null; }

    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм смены ключа для OMAC-ACPKM
    ///////////////////////////////////////////////////////////////////////////////
    private static class MasterACPKM extends KeyDerive
    {
        // режим CTR-ACPKM
        private final BlockMode mode; private Transform transform; 
            
        // последние сгенерированные ключи и их размер
        private byte[] encrypted; private int length; private final int blockSize; 

        // конструктор
        public MasterACPKM(Cipher cipher, int N) throws IOException 
        { 
            // выделить буфер для синхропосылки
            blockSize = cipher.blockSize(); byte[] iv = new byte[blockSize / 2]; 

            // инициализировать синхропосылку
            for (int i = 0; i < iv.length; i++) iv[i] = (byte)0xFF; 

            // указать параметры алгоритма
            CipherMode.CTR parameters = new CipherMode.CTR(iv, cipher.blockSize()); 

            // создать алгоритм смены ключа
            try (KeyDerive keyMeshing = new ACPKM(cipher))
            { 
                // создать режим CTR
                mode = new CTR(cipher, parameters, keyMeshing, N); 
            }
            // инициализировать переменные
            transform = null; encrypted = new byte[0]; length = 0; 
        }  
        // освободить ресурсы
        @Override protected void onClose() throws IOException    
        { 
            // обнулить сгенерированные ключи
            for (int i = 0; i < encrypted.length; i++) encrypted[i] = 0; 

            // освободить ресурсы
            RefObject.release(transform); RefObject.release(mode); super.onClose();
        }
	    // инициализировать алгоритм
	    public final void init(ISecretKey key) throws IOException, InvalidKeyException
        {
            // освободить ресурсы
            RefObject.release(transform); transform = null; length = 0; 

            // создать преобразование режима
            transform = mode.createEncryption(key, PaddingMode.NONE); transform.init();
        }
        // сгенерировать ключевую информацию
        private void update(int deriveSize) throws IOException
        {
            // проверить достаточность данных
            if (length >= deriveSize + blockSize) return;
                
            // определить дополнительный размер данных
            int dataLength = (deriveSize + blockSize) - length; 

            // выравняить размер на границу блока
            dataLength = (dataLength + blockSize - 1) / blockSize * blockSize; 

            // изменить размер буфера
            encrypted = Arrays.copyOf(encrypted, length + dataLength); 

            // создать буфер нулевых данных
            byte[] buffer = new byte[dataLength]; 

            // зашифровать данные
            transform.update(buffer, 0, dataLength, encrypted, length); length += dataLength;
        }
	    // завершить преобразование
	    public final void finish() throws IOException 
        {
            // обнулить сгенерированные ключи
            for (int i = 0; i < encrypted.length; i++) encrypted[i] = 0; 

            // освободить ресурсы
            RefObject.release(transform); transform = null; 
        }
	    // наследовать ключ
	    @Override public ISecretKey deriveKey(ISecretKey key, 
            byte[] iv, SecretKeyFactory keyFactory, int deriveSize) throws IOException
        {
            // указать размер генерируемого ключа
            if (deriveSize < 0) deriveSize = 32; 

            // сбросить старые данные
            if (length > 0) { length -= deriveSize + blockSize; 

                // сместить буфер
                System.arraycopy(encrypted, deriveSize + blockSize, encrypted, 0, length); 
            }
            // выделить память для ключа
            byte[] derivedKey = new byte[deriveSize]; update(deriveSize);

            // скопировать ключ
            System.arraycopy(encrypted, 0, derivedKey, 0, deriveSize); 

            // вернуть созданный ключ
            return keyFactory.create(derivedKey); 
        }
        // дополнительный ключ
        public final byte[] getXorK1(int deriveSize) 
        {  
            // выделить память для блока
            byte[] block = new byte[blockSize]; 

            // скопировать блок
            System.arraycopy(encrypted, deriveSize, block, 0, blockSize); return block; 
        }
    }
}
