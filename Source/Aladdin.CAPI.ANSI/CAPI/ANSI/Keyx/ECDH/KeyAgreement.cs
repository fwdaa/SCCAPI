using System;

namespace Aladdin.CAPI.ANSI.Keyx.ECDH
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа Elliptic Curve Diffie-Hellman
    ///////////////////////////////////////////////////////////////////////////
    public class KeyAgreement : CAPI.KeyAgreement
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // алгоритм наследования ключа
        private KeyDerive keyDerive; private bool useCofactor; 
        // параметры алгоритма шифрования ключа
        private ASN1.ISO.AlgorithmIdentifier keyWrapParameters; 
    
        // конструктор
        public KeyAgreement(bool useCofactor, KeyDerive keyDerive, 
            ASN1.ISO.AlgorithmIdentifier keyWrapParameters)
        { 
            // сохранить переданные параметры
            this.keyDerive = RefObject.AddRef(keyDerive); 
        
            // сохранить переданные параметры
            this.useCofactor = useCofactor; this.keyWrapParameters = keyWrapParameters; 
        } 
        // конструктор
        public KeyAgreement(bool useCofactor, CAPI.Hash hashAlgorithm, 
            ASN1.ISO.AlgorithmIdentifier keyWrapParameters)
        { 
            // сохранить переданные параметры
            this.keyDerive = new Derive.X963KDF(hashAlgorithm); 
            
            // сохранить переданные параметры
            this.useCofactor = useCofactor; this.keyWrapParameters = keyWrapParameters; 
        } 
        // конструктор
        public KeyAgreement(bool useCofactor)
        { 
            // сохранить переданные параметры
            this.keyDerive = new CAPI.Derive.NOKDF(Endian); 
        
            // сохранить переданные параметры
            this.useCofactor = useCofactor; this.keyWrapParameters = null; 
        } 
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(keyDerive); base.OnDispose();
        }
        // сгенерировать случайные данные
        public override byte[] Generate(IParameters parameters, IRand rand)
        {
            // проверить необходимость генерации
            if (keyDerive is CAPI.Derive.NOKDF) return null; 

            // сгенерировать случайные данные
            byte[] random = new byte[64]; rand.Generate(random, 0, 64); return random;   
        }
        // наследовать ключ
        public override ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // преобразовать тип данных
            X962.IPrivateKey ecPrivateKey = (X962.IPrivateKey)privateKey; 
            X962.IPublicKey  ecPublicKey  = (X962.IPublicKey )publicKey; 

            // получить параметры алгоритма
            X962.IParameters ecParameters = (X962.IParameters)privateKey.Parameters; 
        
            // получить параметры эллиптической кривой
            EC.Curve ec = ecParameters.Curve; 
        
            // вычислить точку на эллиптической кривой
            EC.Point P = ec.Multiply(ecPublicKey.Q, ecPrivateKey.D); 
        
            // выполнить дополнительное умножение
            if (useCofactor) P = ec.Multiply(P, ecParameters.Cofactor); 

            // при наличии параметров шифрования
            if (keyWrapParameters != null)
            {
                // закодировать случайные данные
                ASN1.OctetString entityUInfo = (random != null) ? new ASN1.OctetString(random) : null; 

                // закодировать размер ключа в битах
                ASN1.OctetString suppPubInfo = new ASN1.OctetString(
                    Math.Convert.FromInt32(keySize * 8, Endian)
                );
                // объединить закодированные данные
                ASN1.ANSI.X962.SharedInfo sharedInfo = new ASN1.ANSI.X962.SharedInfo(
                    keyWrapParameters, entityUInfo, null, suppPubInfo, null
                ); 
                // получить закодированное представление
                random = sharedInfo.Encoded; 
            }
            // определить размер закодированного представления
            int cb = (ec.Field.FieldSize + 7) / 8; 
        
            // закодировать координату точки
            byte[] encodedX = Math.Convert.FromBigInteger(P.X, Endian, cb); 

            // закодировать координату точки
            using (ISecretKey z = keyDerive.KeyFactory.Create(encodedX))
            {
                // выполнить наследование ключа
                return keyDerive.DeriveKey(z, random, keyFactory, keySize); 
            }
        }
    }
}
