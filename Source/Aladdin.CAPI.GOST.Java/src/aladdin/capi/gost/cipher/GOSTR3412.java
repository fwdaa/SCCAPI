package aladdin.capi.gost.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import aladdin.capi.CipherMode; 
import java.io.*; 
import java.util.Arrays;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ГОСТ P34.12-2015
///////////////////////////////////////////////////////////////////////////
public final class GOSTR3412 extends BlockCipher
{
    // режим смены ключа и размер смены ключа
    private final KeyDerive keyMeshing; private final int N; 
   
    // создание алгоритма из фабрики
    public static IBlockCipher create(Factory factory, 
        SecurityStore scope, int blockSize) throws IOException
    {
        // указать идентификатор алгоритма
        String oid = (blockSize == 8) ? OID.GOSTR3412_64 : OID.GOSTR3412_128; 
        
        // закодировать параметры алгоритма
        AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(oid), Null.INSTANCE
        );
        // получить алгоритм шифрования блока
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
        {
            // проверить наличие алгоритма шифрования блока
            if (cipher == null) return null; 
            
            // вернуть алгоритм шифрования
            return new GOSTR3412(cipher, PaddingMode.ANY); 
        }
    }
    public static Cipher createCTR_ACPKM(Factory factory, 
        SecurityStore scope, int blockSize, byte[] iv) throws IOException
    {
        // указать идентификатор алгоритма
        String oid = (blockSize == 8) ? OID.GOSTR3412_64 : OID.GOSTR3412_128; 
        
        // указать размер смены ключа
        int N = (blockSize == 8) ? (8 * 1024) : (256 * 1024); 
        
        // закодировать параметры алгоритма
        AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(oid), Null.INSTANCE
        );
        // получить алгоритм шифрования блока
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
        {
            // проверить наличие алгоритма шифрования блока
            if (cipher == null) return null; 
            
            // создать алгоритм смены ключа для OMAC-ACPKM
            try (KeyDerive keyMeshing = new aladdin.capi.gost.derive.ACPKM(cipher))
            {
                // указать синхропосылку для шифрования
                byte[] ivCTR = Arrays.copyOf(iv, iv.length - 8); 
                
                // указать параметры режима
                CipherMode.CTR ctrParameters = new CipherMode.CTR(ivCTR, cipher.blockSize()); 
                            
                // создать режим CTR со специальной сменой ключа
                return new aladdin.capi.gost.mode.gostr3412.CTR(
                    cipher, ctrParameters, keyMeshing, N
                ); 
            }
        }
    }
    public static Cipher createCTR_ACPKM_OMAC(Factory factory, 
        SecurityStore scope, int blockSize, byte[] iv) throws IOException
    {
        // создать блочный алгоритм шифрования
        try (IBlockCipher blockCipher = create(factory, scope, blockSize))
        {
            // создать режим CTR со специальной сменой ключа
            try (Cipher ctrACPKM = createCTR_ACPKM(factory, scope, blockSize, iv))
            {
                // указать начальную синхропосылку
                byte[] start = new byte[blockSize]; 

                // создать алгоритм выработки имитовставки
                try (Mac omac = aladdin.capi.mac.OMAC1.create(blockCipher, start))
                {
                    // закодировать параметры алгоритма
                    AlgorithmIdentifier hmacParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_HMAC_256), Null.INSTANCE
                    );
                    // создать алгоритм HMAC
                    try (Mac hmac = (Mac)factory.createAlgorithm(scope, hmacParameters, Mac.class))
                    {
                        // проверить наличие алгоритма шифрования блока
                        if (hmac == null) return null; byte[] seed = new byte[8];

                        // указать синхропосылку для генерации ключей
                        System.arraycopy(iv, iv.length - 8, seed, 0, seed.length);
                        
                        // обьединить имитовставку с режимом
                        return new GOSTR3412ACPKM_MAC(ctrACPKM, omac, hmac, seed); 
                    }
                }
            }
        }
    }
    // конструктор
	public GOSTR3412(Cipher gostr3412, KeyDerive keyMeshing, int N, PaddingMode padding)  
    {
		// сохранить переданные параметры
		super(gostr3412, padding); this.N = N; 
        
		// указать способ смены ключа
        this.keyMeshing = RefObject.addRef(keyMeshing); 
	}
    // конструктор
	public GOSTR3412(Cipher gostr3412, PaddingMode padding)  
    {
		// смена ключа отсутствует
        super(gostr3412, padding); keyMeshing = null; N = 0; 
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
                engine(), keyMeshing, N, padding()
            );  
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // вернуть режим шифрования CBC
            return new aladdin.capi.gost.mode.gostr3412.CBC(
                engine(), (CipherMode.CBC)mode, keyMeshing, N, padding()
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
