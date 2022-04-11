using System;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3412
{
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритм согласования ключа
    ////////////////////////////////////////////////////////////////////////////
    public class KExp15Agreement : CAPI.TransportAgreement
    {
        // создать алгоритм SSDH
        public new static TransportAgreement CreateSSDH(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters)
        {
            // определить идентификатор алгоритма
            string oid = parameters.Algorithm.Value; int blockSize = 0; 
        
            // указать идентификатор алгоритма шифрования
            if (oid == ASN1.GOST.OID.gostR3412_64_wrap_kexp15 ) blockSize =  8; else 
            if (oid == ASN1.GOST.OID.gostR3412_128_wrap_kexp15) blockSize = 16; 
        
            // при ошибке выбросить исключение
            else throw new NotSupportedException();
        
            // извлечь синхропосылку
            byte[] iv = new byte[blockSize / 2]; 
        
            // создать алгоритм шифрования ключа
            using (KeyWrap keyWrap = GOST.Wrap.KExp15.Create(factory, scope, blockSize, iv))
            {
                // проверить поддержку алгоритма
                if (keyWrap == null) return null;  
            }
            // указать параметры согласования ключа
            oid = new ASN1.GOST.GOSTR3410KEGParameters(parameters.Parameters).Algorithm.Value;
             
            // в зависимости от идентификатора алгоритма
            if (oid == ASN1.GOST.OID.gostR3410_2012_DH_256)
            {
                // указать параметры алгоритма HMAC
                ASN1.ISO.AlgorithmIdentifier hmacPrameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_256), ASN1.Null.Instance
                ); 
                // создать алгоритм вычисления имитовставки
                using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, hmacPrameters))
                {
                    // проверить наличие алгоритма
                   if (macAlgorithm == null) return null; 
                }
            }
            // в зависимости от идентификатора алгоритма
            else if (oid != ASN1.GOST.OID.gostR3410_2012_DH_512) return null; 

            // создать алгоритм шифрования ключа
            return new KExp15Agreement(parameters); 
        }
        // конструктор
        public KExp15Agreement(ASN1.ISO.AlgorithmIdentifier parameters) : base(parameters) {} 
    
        // получить алгоритм согласования ключа
        protected override KeyAgreement CreateKeyAgreementAlgorithm(
            CAPI.Factory factory, SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters)
        {
            // определить идентификатор алгоритма
            string oid = new ASN1.GOST.GOSTR3410KEGParameters(parameters.Parameters).Algorithm.Value; 

            // в зависимости от идентификатора алгоритма
            if (oid == ASN1.GOST.OID.gostR3410_2012_DH_256)
            {
                // указать параметры алгоритма HMAC
                ASN1.ISO.AlgorithmIdentifier hmacPrameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_256), ASN1.Null.Instance
                ); 
                // создать алгоритм вычисления имитовставки
                using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, hmacPrameters))
                {
                    // проверить наличие алгоритма
                   if (macAlgorithm == null) throw new NotSupportedException(); 
                        
                    // создать алгоритм
                    return new KEG2012_256(macAlgorithm); 
                }
            }
            // в зависимости от идентификатора алгоритма создать алгоритм
            if (oid == ASN1.GOST.OID.gostR3410_2012_DH_512) return new KEG2012_512();

            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
        // получить алгоритм шифрования ключа
        protected override KeyWrap CreateKeyWrapAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, byte[] random)
        {
            // определить идентификатор алгоритма
            string oid = parameters.Algorithm.Value; int blockSize = 0; 
        
            // указать идентификатор алгоритма шифрования
            if (oid == ASN1.GOST.OID.gostR3412_64_wrap_kexp15 ) blockSize =  8; else 
            if (oid == ASN1.GOST.OID.gostR3412_128_wrap_kexp15) blockSize = 16; 
        
            // при ошибке выбросить исключение
            else throw new NotSupportedException();
        
            // извлечь синхропосылку
            byte[] iv = new byte[blockSize / 2]; Array.Copy(random, 24, iv, 0, iv.Length);
        
            // создать алгоритм шифрования ключа
            KeyWrap keyWrap = GOST.Wrap.KExp15.Create(factory, scope, blockSize, iv); 
        
            // проверить наличие алгоритма
            if (keyWrap == null) throw new NotSupportedException(); return keyWrap; 
        }
    }
}
