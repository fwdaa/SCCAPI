package aladdin.capi.gost.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ГОСТ P34.12-2015 
///////////////////////////////////////////////////////////////////////////
public final class GOSTR3412 extends BlockCipher
{
    // режим смены ключа и размер смены ключа
    private final KeyDerive keyMeshing; private final int N; 
   
    // создать блочный алгоритм шифрования без смены ключа
    public static IBlockCipher create(Factory factory, 
        SecurityStore scope, int blockSize) throws IOException
    {
        // указать идентификатор алгоритма
        String oid = (blockSize == 8) ? OID.GOSTR3412_64 : OID.GOSTR3412_128; 
        
        // получить алгоритм шифрования блока
        try (Cipher cipher = (Cipher)factory.createAlgorithm(
            scope, oid, Null.INSTANCE, Cipher.class))
        {
            // вернуть алгоритм шифрования
            return (cipher != null) ? new GOSTR3412(cipher) : null; 
        }
    }
    // создать блочный алгоритм шифрования со сменой ключа ACPKM
    public static IBlockCipher createACPKM(Factory factory, 
        SecurityStore scope, int blockSize) throws IOException
    {
        // указать идентификатор алгоритма
        String oid = (blockSize == 8) ? OID.GOSTR3412_64 : OID.GOSTR3412_128; 
        
        // указать размер смены ключа
        int N = (blockSize == 8) ? (8 * 1024) : (256 * 1024); 
        
        // получить алгоритм шифрования блока
        try (Cipher cipher = (Cipher)factory.createAlgorithm(
            scope, oid, Null.INSTANCE, Cipher.class))
        {
            // проверить наличие алгоритма шифрования блока
            if (cipher == null) return null; 
            
            // создать алгоритм смены ключа ACPKM
            try (KeyDerive keyMeshing = new aladdin.capi.gost.derive.ACPKM(cipher))
            {
                // вернуть алгоритм шифрования
                return new GOSTR3412(cipher, keyMeshing, N); 
            }
        }
    }
    // создать режим шифрования CTR
    public static Cipher createCTR(Factory factory, 
        SecurityStore scope, int blockSize, byte[] iv) throws IOException
    {
        // указать имя алгоритма
        String name = (blockSize == 8) ? "GOST3412_2015_M" : "GOST3412_2015_K"; 
        
        // создать блочный алгоритм шифрования 
        try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
            scope, name, Null.INSTANCE, IBlockCipher.class))
        {
            // проверить наличие алгоритма
            if (blockCipher == null) return null; 
            
            // создать режим CTR
            return blockCipher.createBlockMode(new CipherMode.CTR(iv, blockSize)); 
        }
    }
    // создать режим шифрования CTR со сменой ключа ACPKM
    public static Cipher createCTR_ACPKM(Factory factory, 
        SecurityStore scope, int blockSize, byte[] iv) throws IOException
    {
        // создать блочный алгоритм шифрования 
        try (IBlockCipher blockCipher = createACPKM(factory, scope, blockSize))
        {
            // проверить наличие алгоритма
            if (blockCipher == null) return null; 
            
            // создать режим CTR
            return blockCipher.createBlockMode(new CipherMode.CTR(iv, blockSize)); 
        }
    }
    // создать алгоритм вычисления имитовставки
    public static Mac createOMAC(Factory factory, 
        SecurityStore scope, int blockSize) throws IOException
    {
        // указать имя алгоритма
        String name = (blockSize == 8) ? "GOST3412_2015_M" : "GOST3412_2015_K"; 
        
        // создать блочный алгоритм шифрования
        try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
            scope, name, Null.INSTANCE, IBlockCipher.class))
        {
            // проверить наличие алгоритма
            if (blockCipher == null) return null; byte[] start = new byte[blockSize]; 
            
            // создать алгоритм выработки имитовставки
            return aladdin.capi.mac.OMAC1.create(blockCipher, start); 
        }
    }
    // конструктор
	public GOSTR3412(Cipher gostr3412, KeyDerive keyMeshing, int N)  
    {
		// сохранить переданные параметры
		super(gostr3412); this.N = N; 
        
		// указать способ смены ключа
        this.keyMeshing = RefObject.addRef(keyMeshing); 
	}
    // конструктор
	public GOSTR3412(Cipher gostr3412)  
    {
		// смена ключа отсутствует
        super(gostr3412); keyMeshing = null; N = 0; 
    }
    // освободить ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить ресурсы
        RefObject.release(keyMeshing); super.onClose();
    }
    // режим смены ключа
    protected KeyDerive keyMeshing() { return keyMeshing; }
    
    // создать режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode)  
    {
        if (mode instanceof CipherMode.ECB) 
        {
            // вернуть режим шифрования ECB
            return new aladdin.capi.gost.mode.gostr3412.ECB(
                engine(), keyMeshing, N, PaddingMode.ANY
            );  
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // вернуть режим шифрования CBC
            return new aladdin.capi.gost.mode.gostr3412.CBC(
                engine(), (CipherMode.CBC)mode, keyMeshing, N, PaddingMode.ANY
            );  
        }
        if (mode instanceof CipherMode.CFB) 
        {
            // вернуть режим шифрования CFB
            return new aladdin.capi.gost.mode.gostr3412.CFB(
                engine(), (CipherMode.CFB)mode, keyMeshing, N
            );  
        }
        if (mode instanceof CipherMode.OFB) 
        {
            // вернуть режим шифрования OFB
            return new aladdin.capi.gost.mode.gostr3412.OFB(
                engine(), (CipherMode.OFB)mode, keyMeshing, N
            );  
        }
        if (mode instanceof CipherMode.CTR) 
        {
            // вернуть режим шифрования CFB
            return new aladdin.capi.gost.mode.gostr3412.CTR(
                engine(), (CipherMode.CTR)mode, keyMeshing, N
            );  
        }
        // при ошибке выбросить исключение
        throw new UnsupportedOperationException(); 
    }
}
