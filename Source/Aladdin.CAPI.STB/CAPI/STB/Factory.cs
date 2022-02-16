using System; 
using System.IO; 

//////////////////////////////////////////////////////////////////////////////
// Фабрика создания алгоритмов
//////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB
{
    public class Factory : CAPI.Factory
    {
	    ///////////////////////////////////////////////////////////////////////
        // Фиксированные таблицы подстановок
	    ///////////////////////////////////////////////////////////////////////
        public static readonly byte[] SBox1 = ASN1.STB.SBoxReference.DecodeSBox(
            ASN1.STB.SBoxReference.Parameters(ASN1.STB.OID.gost28147_sblock_1)
        ); 
	    ///////////////////////////////////////////////////////////////////////
	    // Поддерживаемые фабрики кодирования ключей
	    ///////////////////////////////////////////////////////////////////////
	    public override KeyFactory[] KeyFactories() 
	    {
            // вернуть список фабрик
            return new KeyFactory[] { 
                new STB.STB34101.KeyFactory      (ASN1.STB.OID.stb34101_bign_pubKey      ), 
                new STB.STB11762.BDSBDHKeyFactory(ASN1.STB.OID.stb11762_bdsbdh_pubKey    ), 
                new STB.STB11762.BDSBDHKeyFactory(ASN1.STB.OID.stb11762_pre_bdsbdh_pubKey), 
                new STB.STB11762.BDSKeyFactory   (ASN1.STB.OID.stb11762_bds_pubKey       ), 
                new STB.STB11762.BDSKeyFactory   (ASN1.STB.OID.stb11762_pre_bds_pubKey   ) 
            }; 
	    }
	    ///////////////////////////////////////////////////////////////////////
        // Используемые алгоритмы по умолчанию
	    ///////////////////////////////////////////////////////////////////////
        public override CAPI.Culture GetCulture(SecurityStore scope, string keyOID)
        {
            if (keyOID == ASN1.STB.OID.stb34101_bign_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB34101_256(); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_pre_bdsbdh_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176Pro(ASN1.STB.OID.gost28147_sblock_1); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_bdsbdh_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176(ASN1.STB.OID.gost28147_sblock_1); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_pre_bds_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176Pro(ASN1.STB.OID.gost28147_sblock_1); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_bds_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176(ASN1.STB.OID.gost28147_sblock_1); 
            }
            return null; 
        }
        // указать используемые алгоритмы
        public override PBE.PBECulture GetCulture(PBE.PBEParameters parameters, string keyOID)
        {
            if (keyOID == ASN1.STB.OID.stb34101_bign_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB34101_256.PKCS12(parameters); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_bds_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176.PKCS12(
                    parameters, ASN1.STB.OID.gost28147_sblock_1
                ); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_bdsbdh_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176.PKCS12(
                    parameters, ASN1.STB.OID.gost28147_sblock_1
                ); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_pre_bds_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176Pro.PKCS12(
                    parameters, ASN1.STB.OID.gost28147_sblock_1
                ); 
            }
            if (keyOID == ASN1.STB.OID.stb11762_pre_bdsbdh_pubKey) 
            {
                // вернуть параметры по умолчанию
                return new Culture.STB1176Pro.PKCS12(
                    parameters, ASN1.STB.OID.gost28147_sblock_1
                ); 
            }
            return null; 
        }
	    ///////////////////////////////////////////////////////////////////////
	    // Cоздать алгоритм генерации ключей
	    ///////////////////////////////////////////////////////////////////////
	    protected override KeyPairGenerator CreateGenerator(
            CAPI.Factory factory, SecurityObject scope, 
            IRand rand, string keyOID, IParameters parameters)
	    {
		    if (keyOID == ASN1.STB.OID.stb11762_pre_bdsbdh_pubKey || 
                keyOID == ASN1.STB.OID.stb11762_bdsbdh_pubKey) 
		    {
                // преобразовать тип параметров
                STB11762.IBDSBDHParameters stbParameters = (STB11762.IBDSBDHParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new STB11762.BDSBDHKeyPairGenerator(factory, scope, rand, stbParameters); 
		    }
		    if (keyOID == ASN1.STB.OID.stb11762_pre_bds_pubKey || 
                keyOID == ASN1.STB.OID.stb11762_bds_pubKey) 
		    {
                // преобразовать тип параметров
                STB11762.IBDSParameters stbParameters = (STB11762.IBDSParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new STB11762.BDSKeyPairGenerator(factory, scope, rand, stbParameters); 
		    }
		    if (keyOID == ASN1.STB.OID.stb34101_bign_pubKey) 
		    {
                // преобразовать тип параметров
                STB.STB34101.IParameters stbParameters = (STB.STB34101.IParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new STB.STB34101.KeyPairGenerator(factory, scope, rand, stbParameters); 
            }
		    return null; 
	    }
	    ///////////////////////////////////////////////////////////////////////
	    // Cоздать алгоритм для параметров
	    ///////////////////////////////////////////////////////////////////////
	    protected override IAlgorithm CreateAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, Type type) 
	    {
		    // определить идентификатор алгоритма
		    String oid = parameters.Algorithm.Value; for (int i = 0; i < 1; i++)
            { 
		        // для алгоритмов хэширования
		        if (type == typeof(CAPI.Hash))
		        {
			        if (oid == ASN1.STB.OID.stb11761_hash) 
			        {
			            // раскодировать параметры
			            ASN1.OctetString start = new ASN1.OctetString(parameters.Parameters); 
            
			            // создать алгоритм хэширования
			            return new Hash.STB11761(start.Value); 
			        }
		        }
		        // для алгоритмов вычисления имитовставки
		        else if (type == typeof(Mac))
		        {
			        if (oid == ASN1.STB.OID.gost28147_mac) 
                    {
			            // раскодировать параметры
                        ASN1.STB.GOSTSBlock algParameters = new ASN1.STB.GOSTSBlock(parameters.Parameters); 
            
                        // проверить наличие таблицы подстановок
                        if (ASN1.Encodable.IsNullOrEmpty(algParameters.SBlock)) break; 
                        
                        // проверить явное указание таблицы подстановок
                        if (algParameters.SBlock.Tag != ASN1.Tag.OctetString) break; 
                        
                        // раскодировать таблицу подстановок
                        ASN1.OctetString encodedSBox = new ASN1.OctetString(algParameters.SBlock); 

                        // рскодировать таблицу подстановок
                        byte[] sbox = ASN1.STB.SBoxReference.DecodeSBox(encodedSBox); 

                        // создать алгоритм вычисления имитовставки
                        return new GOST.MAC.GOST28147(sbox); 
                    }
		        }
		        // для алгоритмов шифрования блока
		        else if (type == typeof(CAPI.Cipher))
		        {
			        if (oid == ASN1.STB.OID.gost28147_ecb) 
                    {
				        // раскодировать параметры
                        ASN1.STB.GOSTSBlock algParameters = new ASN1.STB.GOSTSBlock(parameters.Parameters); 
                
                        // проверить наличие таблицы подстановок
                        if (ASN1.Encodable.IsNullOrEmpty(algParameters.SBlock)) break; 
                        
                        // проверить явное указание таблицы подстановок
                        if (algParameters.SBlock.Tag != ASN1.Tag.OctetString) break; 

                        // раскодировать таблицу подстановок
                        ASN1.OctetString encodedSBox = new ASN1.OctetString(algParameters.SBlock); 

                        // раскодировать таблицу подстановок
                        byte[] sbox = ASN1.STB.SBoxReference.DecodeSBox(encodedSBox);

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new GOST.Engine.GOST28147(sbox))
                        {
                             // создать алгоритм шифрования
                             return new GOST.Mode.GOST28147.ECB(engine); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_ecb_128) 
			        {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {16}))
                        {
                            // создать алгоритм
                            return new Mode.STB34101.ECB(engine); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_ecb_192) 
			        {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {24}))
                        {
                            // создать алгоритм
                            return new Mode.STB34101.ECB(engine); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_ecb_256) 
			        {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {32}))
                        {
                            // создать алгоритм
                            return new Mode.STB34101.ECB(engine); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_cbc_128) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {16}))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new Mode.STB34101.CBC(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_cbc_192) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {24}))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new Mode.STB34101.CBC(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_cbc_256) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {32}))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new Mode.STB34101.CBC(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_cfb_128) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {16}))
                        {
                            // указать используемый режим
                            CipherMode.CFB mode = new CipherMode.CFB(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new CAPI.Mode.CFB(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_cfb_192) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {24}))
                        {
                            // указать используемый режим
                            CipherMode.CFB mode = new CipherMode.CFB(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new CAPI.Mode.CFB(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_cfb_256) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {32}))
                        {
                            // указать используемый режим
                            CipherMode.CFB mode = new CipherMode.CFB(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new CAPI.Mode.CFB(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_ctr_128) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {16}))
                        {
                            // указать используемый режим
                            CipherMode.CTR mode = new CipherMode.CTR(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new Mode.STB34101.CTR(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_ctr_192) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {24}))
                        {
                            // указать используемый режим
                            CipherMode.CTR mode = new CipherMode.CTR(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new Mode.STB34101.CTR(engine, mode); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_ctr_256) 
			        {
                        // извлечь синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.STB34101(new int[] {32}))
                        {
                            // указать используемый режим
                            CipherMode.CTR mode = new CipherMode.CTR(iv.Value, engine.BlockSize); 

                            // создать алгоритм
                            return new Mode.STB34101.CTR(engine, mode); 
                        }
                    }
                }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(SignHash))
		        {
                    if (oid == ASN1.STB.OID.stb34101_bign_hbelt) 
			        {
                        // указать идентификатор алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
                        ); 
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {  
                            // проверить наличие алгоритма
                            if (hash == null) break; return new Sign.STB34101.SignHash(hash);
                        }
                    }
		        }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(VerifyHash))
		        {
			        if (oid == ASN1.STB.OID.stb34101_bign_hbelt) 
			        {
                        // указать идентификатор алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
                        ); 
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {  
                            // проверить наличие алгоритма
                            if (hash == null) break; return new Sign.STB34101.VerifyHash(hash);
                        }
                    }
		        }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(SignData))
		        {
                    if (oid == ASN1.STB.OID.stb11762_sign)
                    {
                        // создать алгоритм подписи данных
                        return new Sign.STB11762.SignData(); 
                    }
		        }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(VerifyData))
		        {
			        if (oid == ASN1.STB.OID.stb11762_sign)
                    {
                        // создать алгоритм проверки подписи данных
                        return new Sign.STB11762.VerifyData(); 
                    }
		        }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(IKeyAgreement))
		        {
                    // создать алгоритм согласования общего ключа
			        if (oid == ASN1.STB.OID.stb11762_bdh_oneSide)
                    { 
                        // создать алгоритм согласования общего ключа
                        return new Keyx.STB11762.KeyAgreement(); 
                    }
                }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(TransportKeyWrap))
		        {
			        if (oid == ASN1.STB.OID.stb34101_bign_keyTransport) 
			        {
                        // при наличии параметров
                        if (!ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        {
                            // раскодировать параметры алгоритма
                            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                            // создать алгоритм шифрования ключа
                            using (KeyWrap keyWrap = factory.CreateAlgorithm<KeyWrap>(scope, wrapParameters))
                            {  
                                // проверить поддержку алгоритма
                                if (keyWrap == null) break; 
            
			                    // создать алгоритм согласования общего ключа
                                return new Keyx.STB34101.TransportKeyWrap(keyWrap);
                            }
                        }
                    }
		        }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(TransportKeyUnwrap))
		        {
                    if (oid == ASN1.STB.OID.stb34101_bign_keyTransport) 
			        {
                        // при наличии параметров
                        if (!ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        {
                            // раскодировать параметры алгоритма
                            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                            // создать алгоритм шифрования ключа
                            using (KeyWrap keyWrap = factory.CreateAlgorithm<KeyWrap>(scope, wrapParameters))
                            {  
                                // проверить поддержку алгоритма
                                if (keyWrap == null) break; 
            
			                    // создать алгоритм согласования общего ключа
                                return new Keyx.STB34101.TransportKeyUnwrap(keyWrap); 
                            }
                        }
                    }
		        }
            }
            // вызвать базовую функцию
            return Factory.RedirectAlgorithm(factory, scope, parameters, type); 
	    }
	    ///////////////////////////////////////////////////////////////////////
	    // Перенаправление алгоритмов
	    ///////////////////////////////////////////////////////////////////////
	    public static new IAlgorithm RedirectAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, Type type) 
        {
		    // определить идентификатор алгоритма
		    String oid = parameters.Algorithm.Value; for (int i = 0; i < 1; i++)
            { 
		        // для алгоритмов хэширования
		        if (type == typeof(CAPI.Hash))
		        {
                    if (oid == ASN1.STB.OID.stb11761_hash0) 
                    {
                        // указать стартовое хэш-значение
                        byte[] start = new byte[] { 
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 
                        }; 
                        // указать идентификатор алгоритма
                        ASN1.ObjectIdentifier algOID = new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hash); 
                
                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(algOID, new ASN1.OctetString(start)); 
                
                        // создать алгоритм
                        return factory.CreateAlgorithm<CAPI.Hash>(scope, parameters); 
                    }
                    if (oid == ASN1.STB.OID.stb11761_hashA) 
                    {
                        // указать стартовое хэш-значение
                        byte[] start = new byte[] { 
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
                        }; 
                        // указать идентификатор алгоритма
                        ASN1.ObjectIdentifier algOID = new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hash); 
                
                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(algOID, new ASN1.OctetString(start)); 
                
                        // создать алгоритм
                        return factory.CreateAlgorithm<CAPI.Hash>(scope, parameters); 
                    }
                    if (oid == ASN1.STB.OID.stb11761_hash4E) 
                    {
                        // указать стартовое хэш-значение
                        byte[] start = new byte[] { 
                            (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                            (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E,
                            (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E,
                            (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                            (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E,
                            (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                            (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                            (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E
                        }; 
                        // указать идентификатор алгоритма
                        ASN1.ObjectIdentifier algOID = new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hash); 
                
                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(algOID, new ASN1.OctetString(start)); 

                        // создать алгоритм
                        return factory.CreateAlgorithm<CAPI.Hash>(scope, parameters); 
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_hash)
                    {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_256), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм хэширования
                            if (cipher == null) break; return new Hash.STB34101(cipher); 
                        }
                    }
                }
		        // для алгоритмов вычисления имитовставки
		        else if (type == typeof(Mac))
                {
			        if (oid == ASN1.STB.OID.gost28147_mac) 
                    {
				        // раскодировать параметры
                        ASN1.STB.GOSTSBlock algParameters = new ASN1.STB.GOSTSBlock(parameters.Parameters); 
                
                        // при отсутствии таблицы подстановок
                        if (ASN1.Encodable.IsNullOrEmpty(algParameters.SBlock))
                        {
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(
                                ASN1.STB.OID.gost28147_sblock_1
                            ); 
                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTSBlock(encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<Mac>(scope, parameters); 
                        }
                        // при указании идентификатора таблицы подстановок
                        else if (algParameters.SBlock.Tag == ASN1.Tag.ObjectIdentifier)
                        {
                            // указать идентификатор таблицы подстановок
                            ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(algParameters.SBlock); 
                    
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(sboxOID.Value); 

                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTSBlock(encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<Mac>(scope, parameters); 
                        }
                        else break; 
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_mac_128) 
                    {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_128), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм вычисления имитовставки
                            if (cipher == null) break; return new MAC.STB34101(cipher); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_mac_192) 
                    {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_192), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм вычисления имитовставки
                            if (cipher == null) break; return new MAC.STB34101(cipher); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_mac_256) 
                    {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_256), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм вычисления имитовставки
                            if (cipher == null) break; return new MAC.STB34101(cipher); 
                        }
                    }
                    if (oid == ASN1.STB.OID.stb34101_hmac_hspec) 
                    {
                        // раскодировать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 
                
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new CAPI.MAC.HMAC(hashAlgorithm); 
                        }
                    }
                    if (oid == ASN1.STB.OID.stb34101_hmac_hbelt) 
                    {
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), parameters.Parameters
                        ); 
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new CAPI.MAC.HMAC(hashAlgorithm); 
                        }
                    }
                }
		        // для алгоритмов симметричного шифрования
		        else if (type == typeof(CAPI.Cipher))
		        {
			        if (oid == ASN1.STB.OID.gost28147_ecb) 
                    {
				        // раскодировать параметры
                        ASN1.STB.GOSTSBlock algParameters = new ASN1.STB.GOSTSBlock(parameters.Parameters); 
                
                        // при отсутствии таблицы подстановок
                        if (ASN1.Encodable.IsNullOrEmpty(algParameters.SBlock))
                        {
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(
                                ASN1.STB.OID.gost28147_sblock_1
                            ); 
                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTSBlock(encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                        // при указании идентификатора таблицы подстановок
                        else if (algParameters.SBlock.Tag == ASN1.Tag.ObjectIdentifier)
                        {
                            // указать идентификатор таблицы подстановок
                            ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(algParameters.SBlock); 
                    
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(sboxOID.Value); 

                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTSBlock(encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                        else break; 
                    }
			        if (oid == ASN1.STB.OID.gost28147_cfb) 
                    {
				        // раскодировать параметры
                        ASN1.STB.GOSTParams algParameters = new ASN1.STB.GOSTParams(parameters.Parameters); 
                
                        // при отсутствии таблицы подстановок
                        if (ASN1.Encodable.IsNullOrEmpty(algParameters.SBlock))
                        {
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(
                                ASN1.STB.OID.gost28147_sblock_1
                            ); 
                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTParams(algParameters.IV, encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                        // при указании идентификатора таблицы подстановок
                        else if (algParameters.SBlock.Tag == ASN1.Tag.ObjectIdentifier)
                        {
                            // указать идентификатор таблицы подстановок
                            ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(algParameters.SBlock); 
                    
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(sboxOID.Value); 

                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTParams(algParameters.IV, encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                        else { 
                            // проверить наличие синхропосылки
                            if (algParameters.IV == null) throw new IOException(); 

                            // указать параметры алгоритма шифрования блока
                            ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147), 
                                new ASN1.STB.GOSTSBlock(algParameters.SBlock)
                            ); 
                            // создать алгоритм шифрования блока
                            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                                scope, engineParameters))
                            {  
                                // проверить наличие алгоритма
                                if (engine == null) break; 
                    
                                // указать используемый режим
                                CipherMode.CFB mode = new CipherMode.CFB(algParameters.IV.Value, engine.BlockSize); 
                    
                                // создать алгоритм шифрования
                                return new GOST.Mode.GOST28147.CFB(engine, mode); 
                            }
                        }
                    }
			        if (oid == ASN1.STB.OID.gost28147_ctr) 
                    {
				        // раскодировать параметры
                        ASN1.STB.GOSTParams algParameters = new ASN1.STB.GOSTParams(parameters.Parameters); 
                
                        // при отсутствии таблицы подстановок
                        if (ASN1.Encodable.IsNullOrEmpty(algParameters.SBlock))
                        {
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(
                                ASN1.STB.OID.gost28147_sblock_1
                            ); 
                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTParams(algParameters.IV, encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                        // при указании идентификатора таблицы подстановок
                        else if (algParameters.SBlock.Tag == ASN1.Tag.ObjectIdentifier)
                        {
                            // указать идентификатор таблицы подстановок
                            ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(algParameters.SBlock); 
                    
                            // указать таблицу подстановок
                            ASN1.OctetString encodedSBox = ASN1.STB.SBoxReference.Parameters(sboxOID.Value); 

                            // закодировать параметры алгоритма
                            algParameters = new ASN1.STB.GOSTParams(algParameters.IV, encodedSBox); 
                    
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, algParameters
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                        else { 
                            // проверить наличие синхропосылки
                            if (algParameters.IV == null) throw new IOException(); 

                            // указать параметры алгоритма шифрования блока
                            ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147), 
                                new ASN1.STB.GOSTSBlock(algParameters.SBlock)
                            ); 
                            // создать алгоритм шифрования блока
                            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                                scope, engineParameters))
                            {  
                                // проверить наличие алгоритма
                                if (engine == null) break; 

                                // указать используемый режим
                                CipherMode.CTR mode = new CipherMode.CTR(algParameters.IV.Value, engine.BlockSize); 
                    
                                // создать алгоритм шифрования
                                return new GOST.Mode.GOST28147.CTR(engine, mode);
                            } 
                        }
                    }
                }
		        // для алгоритмов наследования ключа
		        else if (type == typeof(KeyDerive))
		        {
			        if (oid == ASN1.STB.OID.stb34101_belt_keyPrep) 
			        {
                        // извлечь уровень ключа
                        ASN1.OctetString D = new ASN1.OctetString(parameters.Parameters); 

                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_256), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм наследования ключа
                            if (cipher == null) break; return new Derive.STB34101(cipher, D.Value); 
                        }
                    }
                }
		        // для алгоритмов шифрования ключа
		        else if (type == typeof(KeyWrap))
		        {
			        if (oid == ASN1.STB.OID.stb34101_belt_keyWrap_128) 
			        {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_256), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм шифрования ключа
                            if (cipher == null) break; return new Wrap.STB34101(cipher); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_keyWrap_192) 
			        {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_192), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм шифрования ключа
                            if (cipher == null) break; return new Wrap.STB34101(cipher); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_belt_keyWrap_256) 
			        {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_ecb_256), ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // создать алгоритм шифрования ключа
                            if (cipher == null) break; return new Wrap.STB34101(cipher); 
                        }
                    }
		        }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(SignHash))
                {
			        if (oid == ASN1.STB.OID.stb11762_sign)
                    {
                        // создать алгоритм подписи данных
                        using (SignData signAlgorithm = factory.CreateAlgorithm<SignData>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (signAlgorithm == null) break; 
                
                            // создать алгоритм подписи хэш-значения
                            return new Sign.STB11762.SignHash(signAlgorithm); 
                        }
                    }
                }
		        // для алгоритмов подписи данных
		        else if (type == typeof(SignData))
		        {
			        if (oid == ASN1.STB.OID.stb11762_pre_sign)
                    {
                        // указать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), ASN1.Null.Instance
                        ); 
                        // получить алгоритм подписи
                        using (SignHash signAlgorithm = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить наличие алгоритма
                            if (signAlgorithm == null) break; 
                    
                            // создать алгоритм подписи данных
                            return new Sign.STB11762.SignDataPro(signAlgorithm); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_bign_hspec)
                    {
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hbelt), ASN1.Null.Instance
                        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм подписи
                            using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                                scope, signHashParameters))
                            {
                                // проверить поддержку алгоритма
                                if (signHash == null) break; 

                                // создать алгоритм подписи данных
                                return new SignHashData(hash, hashParameters, signHash); 
                            }
                        }   
                    }
			        if (oid == ASN1.STB.OID.stb34101_bign_hbelt)
                    {
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
                        );
                        // указать параметры алгоритма подписи
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hspec), hashParameters
                        ); 
                        // создать алгоритм подписи данных
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
                    }
                }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(VerifyHash))
                {
			        if (oid == ASN1.STB.OID.stb11762_sign)
                    {
                        // создать алгоритм проверки подписи данных
                        using (VerifyData verifyAlgorithm = factory.CreateAlgorithm<VerifyData>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (verifyAlgorithm == null) break; 
                
                            // создать алгоритм проверки подписи хэш-значения
                            return new Sign.STB11762.VerifyHash(verifyAlgorithm); 
                        }
                    }
                }
		        // для алгоритмов подписи данных
		        else if (type == typeof(VerifyData))
		        {
			        if (oid == ASN1.STB.OID.stb11762_pre_sign)
                    {
                        // указать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), ASN1.Null.Instance
                        ); 
                        // получить алгоритм подписи
                        using (VerifyHash verifyAlgorithm = factory.CreateAlgorithm<VerifyHash>(
                            scope, verifyHashParameters))
                        {
                            // проверить наличие алгоритма
                            if (verifyAlgorithm == null) break; 

                            // создать алгоритм подписи данных
                            return new Sign.STB11762.VerifyDataPro(verifyAlgorithm); 
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_bign_hspec)
                    {
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hbelt), ASN1.Null.Instance
                        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм проверки подписи
                            using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                                scope, verifyHashParameters))
                            {
                                // проверить поддержку алгоритма
                                if (verifyHash == null) break; 

                                // создать алгоритм проверки подписи данных
                                return new VerifyHashData(hash, hashParameters, verifyHash); 
                            }
                        }
                    }
			        if (oid == ASN1.STB.OID.stb34101_bign_hbelt)
                    {
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
                        );
                        // указать параметры алгоритма подписи
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hspec), hashParameters
                        ); 
                        // создать алгоритм подписи данных
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
                    }
                }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(TransportKeyWrap))
		        {
			        if (oid == ASN1.STB.OID.stb11762_bdh_keyTrans) 
			        {
                        // указать идентификатор таблицы подстановок
                        string sboxOID = ASN1.STB.OID.gost28147_sblock_1; 

                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_ecb), 
                            new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
                        );         
                        // указать параметры алгоритма вычисления имитовставки
                        ASN1.ISO.AlgorithmIdentifier macParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_mac), 
                            new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
                        );
                        // создать блочный алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм вычисления имитовставки
                        using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(
                            scope, macParameters))
                        {
                            // проверить наличие алгоритма
                            if (macAlgorithm == null) break; 
                        }
                        // указать параметры согласования ключа
                        ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_bdh_oneSide), ASN1.Null.Instance
                        );
                        // создать алгоритм согласования ключа
                        using (IKeyAgreement keyAgreement = factory.CreateAlgorithm<IKeyAgreement>(
                            scope, keyAgreementParameters))
                        {
                            // проверить наличие алгоритма
                            if (keyAgreement == null) break;

                            // создать алгоритм
                            return new Keyx.STB11762.TransportKeyWrap(factory, scope, keyAgreement, sboxOID); 
                        } 
			        }
			        if (oid == ASN1.STB.OID.stb34101_bign_keyTransport) 
			        {
                        // при отсутствии параметров
                        if (ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        {
                            // указать параметры алгоритма
                            ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_keyWrap_256), ASN1.Null.Instance
                            ); 
                            // указать идентификатор алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(parameters.Algorithm, wrapParameters); 
                    
                            // создать алгоритм
                            return factory.CreateAlgorithm<TransportKeyWrap>(scope, parameters); 
                        }
                    }
                }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(TransportKeyUnwrap))
		        {
			        if (oid == ASN1.STB.OID.stb11762_bdh_keyTrans) 
			        {
                        // указать идентификатор таблицы подстановок
                        string sboxOID = ASN1.STB.OID.gost28147_sblock_1; 

                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_ecb), 
                            new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
                        );         
                        // указать параметры алгоритма вычисления имитовставки
                        ASN1.ISO.AlgorithmIdentifier macParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_mac), 
                            new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
                        );
                        // создать блочный алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм вычисления имитовставки
                        using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(
                            scope, macParameters))
                        {
                            // проверить наличие алгоритма
                            if (macAlgorithm == null) break; 
                        }
                        // указать параметры согласования ключа
                        ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_bdh_oneSide), ASN1.Null.Instance
                        );
                        // создать алгоритм согласования ключа
                        using (IKeyAgreement keyAgreement = factory.CreateAlgorithm<IKeyAgreement>(
                            scope, keyAgreementParameters))
                        {  
                            // проверить наличие алгоритма
                            if (keyAgreement == null) break; 
                
				            // создать алгоритм согласования общего ключа
				            return new Keyx.STB11762.TransportKeyUnwrap(keyAgreement);
                        }
			        }
			        if (oid == ASN1.STB.OID.stb34101_bign_keyTransport) 
			        {
                        // при отсутствии параметров
                        if (ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        {
                            // указать параметры алгоритма
                            ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_keyWrap_256), ASN1.Null.Instance
                            ); 
                            // указать идентификатор алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(parameters.Algorithm, wrapParameters); 
                    
                            // создать алгоритм
                            return factory.CreateAlgorithm<TransportKeyUnwrap>(scope, parameters); 
                        }
                    }
                }
            }
            // вызвать базовую функцию
            return CAPI.Factory.RedirectAlgorithm(factory, scope, parameters, type); 
        }
    }
}
