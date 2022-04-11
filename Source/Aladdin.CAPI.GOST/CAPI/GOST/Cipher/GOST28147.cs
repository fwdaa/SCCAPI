using System; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.GOST.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования GOST28147-89
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class GOST28147 : RefObject, IBlockCipher
    {
        // создать алгоритм
        public static IBlockCipher Create(CAPI.Factory factory, SecurityStore scope, string paramOID) 
        {
    	    // получить именованные параметры алгоритма
		    ASN1.GOST.GOST28147ParamSet namedParameters = ASN1.GOST.GOST28147ParamSet.Parameters(paramOID);
        
            // указать параметры алгоритма диверсификации
            ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
                 namedParameters.KeyMeshing.Algorithm, new ASN1.ObjectIdentifier(paramOID)
            ); 
            // создать алгоритм диверсификации
            using (KeyDerive kdfAlgorithm = factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
            {
                // проверить наличие алгоритма
                if (kdfAlgorithm == null) return null; 
                    
                // раскодировать таблицу подстановок
                byte[] sbox = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(namedParameters.EUZ); 
                
                // создать алгоритм шифрования блока
                using (CAPI.Cipher engine = new Engine.GOST28147(sbox))
                {
                    // создать блочный алгоритм шифрования
                    return new GOST28147(engine, kdfAlgorithm); 
                }
            }
        }
        // алгоритм шифрования блока и режим смены ключа
        private CAPI.Cipher engine; private KeyDerive keyMeshing;
    
        // конструктор
	    public GOST28147(CAPI.Cipher engine, KeyDerive keyMeshing)  
        {
		    // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); 
        
            // указать способ смены ключа
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
        } 
        // конструктор
	    public GOST28147(CAPI.Cipher engine)  
        {
		    // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); keyMeshing = null;
        }
        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); RefObject.Release(engine); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory { get { return engine.KeyFactory; }}
        // размер блока
	    public int BlockSize { get { return engine.BlockSize; }} 
    
        // создать режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode)  
        {
            if (mode is CipherMode.ECB) 
            {
                // вернуть режим шифрования ECB
                return new Mode.GOST28147.ECB(engine, keyMeshing, PaddingMode.Any);  
            }
            if (mode is CipherMode.CBC) 
            {
                // вернуть режим шифрования CBC
                return new Mode.GOST28147.CBC(
                    engine, (CipherMode.CBC)mode, keyMeshing, PaddingMode.Any
                 );  
            }
            if (mode is CipherMode.CFB) 
            {
                // вернуть режим шифрования CFB
                return new Mode.GOST28147.CFB(engine, (CipherMode.CFB)mode, keyMeshing);  
            }
            if (mode is CipherMode.CTR) 
            {
                // вернуть режим шифрования CFB
                return new Mode.GOST28147.CTR(engine, (CipherMode.CTR)mode, keyMeshing);  
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
    }
}

