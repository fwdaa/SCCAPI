using System; 
using System.IO; 

namespace Aladdin.CAPI.STB.STB34101
{
    ////////////////////////////////////////////////////////////////////////////////
    // Фабрика кодирования кючей
    ////////////////////////////////////////////////////////////////////////////////
    public class KeyFactory : CAPI.KeyFactory
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // конструктор
        public KeyFactory(string keyOID) { this.keyOID = keyOID; }

        // идентификаторы открытых ключей
        public override string KeyOID { get { return keyOID; }} private string keyOID; 
    
	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // указать способ использования ключа
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation       | 
                   KeyUsage.KeyEncipherment; 
        }
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters) 
        {
            // при указании идентификатора 
            if (parameters is INamedParameters)
            {
                // закодировать идентификатор параметров
                return new ASN1.ObjectIdentifier(((INamedParameters)parameters).Oid); 
            }
            else { 
                // преобразовать тип параметров
                IParameters stbParameters = (IParameters)parameters; 
            
                // проверить корректность данных
                if (stbParameters.Generator.X.Signum != 0) throw new NotSupportedException(); 

                // получить параметры эллиптической кривой
                EC.CurveFp ec = stbParameters.Curve; EC.FieldFp field = ec.Field;

                // указать идентификатор типа поля
                ASN1.ObjectIdentifier fieldType = new ASN1.ObjectIdentifier(
                    ASN1.STB.OID.stb34101_bign_primeField
                ); 
                // закодировать параметры поля
                ASN1.STB.FieldID fieldID = new ASN1.STB.FieldID(
                    fieldType, new ASN1.Integer(field.P)
                ); 
                // определить размер координат
                int l = stbParameters.Order.BitLength / 2;
            
                // закодировать параметры a и b кривой
                byte[] A = Math.Convert.FromBigInteger(ec.A, Endian, l / 4);
                byte[] B = Math.Convert.FromBigInteger(ec.B, Endian, l / 4);
            
                // закодировать точку на эллиптической кривой
                byte[] GY = Math.Convert.FromBigInteger(stbParameters.Generator.Y, Endian, l / 4);
            
                // закодировать параметры эллиптичесой кривой
                ASN1.STB.Curve curve = new ASN1.STB.Curve(new ASN1.OctetString(A), 
                    new ASN1.OctetString(B), new ASN1.BitString(ec.Seed)
                ); 
                // закодировать параметры в целом
                return new ASN1.STB.ECParameters(new ASN1.Integer(1), fieldID, curve, 
                    new ASN1.OctetString(GY), new ASN1.Integer(stbParameters.Order), null
                ); 
            }
        }
        // раскодировать параметры
        public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encoded)
        {
            // раскодировать параметры
            encoded = new ASN1.STB.DomainParameters().Decode(encoded); 
        
            // проверить указание параметров
            if (encoded is ASN1.Null) throw new NotSupportedException(); 
        
            // при указании идентификатора
            if (encoded is ASN1.ObjectIdentifier)
            {
                // раскодировать идентификатор параметров
                string oid = ((ASN1.ObjectIdentifier)encoded).Value; 
            
                // раскодировать набор параметров
                return DecodeParameters(oid, ASN1.STB.ECParameters.Parameters(oid)); 
            }
            // раскодировать параметры
            else return DecodeParameters(null, (ASN1.STB.ECParameters)encoded); 
        }
        // раскодировать параметры
        public IParameters DecodeParameters(string oid, ASN1.STB.ECParameters parameters) 
        {
            // проверить корректность параметров
            if (parameters.Cofactor.Value.IntValue != 1) throw new InvalidDataException(); 
        
            // раскодировать модуль простого поля
            Math.BigInteger modulus = parameters.FieldID.Parameters.Value;
        
            // извлечь параметры эллиптической кривой
            ASN1.STB.Curve curve = parameters.Curve; byte[] seed = curve.Seed.Value; 
        
            // раскодировать коэффициенты a и b
            Math.BigInteger a = Math.Convert.ToBigInteger(curve.A.Value, Endian); 
            Math.BigInteger b = Math.Convert.ToBigInteger(curve.B.Value, Endian); 
        
            // раскодировать координаты базовой точки
            Math.BigInteger gy = Math.Convert.ToBigInteger(parameters.Base.Value, Endian); 
        
            // создать базовую точку
            EC.Point g = new EC.Point(Math.BigInteger.Zero, gy);
            try {         
                // создать эллиптическую кривую
                EC.CurveFp ec = new EC.CurveFp(modulus, a, b, seed); 
        
                // раскодировать порядок базовой точки
                Math.BigInteger q = parameters.Order.Value; if (oid == null)
                {
                    // вернуть параметры алгоритма
                    return new Parameters(ec, g, q); 
                }
                // вернуть параметры алгоритма
                else return new NamedParameters(oid, ec, g, q); 
            }
            // при ошибке изменить тип исключения
            catch (ArgumentException e) { throw new InvalidDataException(e.Message, e); }
        }
        // закодировать открытый ключ
        public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(CAPI.IPublicKey publicKey) 
        {
            // выполнить преобразование типа
            IParameters parameters = (IParameters)publicKey.Parameters; 

            // выполнить преобразование типа
            IPublicKey ecPublicKey = (IPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // определить параметр l
            int l = parameters.Order.BitLength / 2; 
        
            // закодировать координаты
            byte[] QX = Math.Convert.FromBigInteger(ecPublicKey.Q.X, Endian, l / 4);
            byte[] QY = Math.Convert.FromBigInteger(ecPublicKey.Q.Y, Endian, l / 4);
        
            // объединить координаты
            ASN1.BitString encoded = new ASN1.BitString(Arrays.Concat(QX, QY));

            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, encoded); 
        }
        // раскодировать открытый ключ
        public override CAPI.IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded) 
        {
            // раскодировать параметры
            IParameters parameters = (IParameters)DecodeParameters(encoded.Algorithm.Parameters); 

            // определить параметр l
            int l = parameters.Order.BitLength / 2; byte[] xy = encoded.SubjectPublicKey.Value; 
        
            // проверить корректность размера
            if (xy.Length != l / 2) throw new InvalidDataException(); 
        
            // раскодировать координаты
            Math.BigInteger QX = Math.Convert.ToBigInteger(xy,     0, l / 4, Endian); 
            Math.BigInteger QY = Math.Convert.ToBigInteger(xy, l / 4, l / 4, Endian); 
        
            // создать точку на эллиптической кривой
            EC.Point q = new EC.Point(QX, QY); 

            // вернуть открытый ключ
            return new PublicKey(this, parameters, q); 
        }
        // закодировать личный ключ
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            CAPI.IPrivateKey privateKey, ASN1.ISO.Attributes attributes) 
        {
            // выполнить преобразование типа
            IParameters parameters = (IParameters)privateKey.Parameters; 

            // выполнить преобразование типа
            IPrivateKey ecPrivateKey = (IPrivateKey)privateKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // определить параметр l
            int l = parameters.Order.BitLength / 2; 
        
            // закодировать значение личного ключа
            ASN1.OctetString encoded = new ASN1.OctetString(
                Math.Convert.FromBigInteger(ecPrivateKey.D, Endian, l / 4)
            );
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(
                new ASN1.Integer(0), algorithm, encoded, attributes
            ); 
        }
        // раскодировать личный ключ
        public override CAPI.IPrivateKey DecodePrivateKey(CAPI.Factory factory,
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // раскодировать параметры
            IParameters parameters = (IParameters)DecodeParameters(
                encoded.PrivateKeyAlgorithm.Parameters
            ); 
            // определить параметр l
            int l = parameters.Order.BitLength / 2; byte[] encodedD = encoded.PrivateKey.Value; 
        
            // проверить корректность размера
            if (encodedD.Length != l / 4) throw new InvalidDataException(); 
        
            // раскодировать значение личного ключа
            Math.BigInteger d = Math.Convert.ToBigInteger(encodedD, Endian); 
        
            // вернуть личный ключ
            return new PrivateKey(factory, null, keyOID, parameters, d); 
        }
        // закодировать пару ключей
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey, 
            ASN1.ISO.Attributes attributes)
        {
            // закодировать личный ключ
            return EncodePrivateKey(privateKey, attributes); 
        }
	    // раскодировать пару ключей
        public override KeyPair DecodeKeyPair(CAPI.Factory factory,  
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // раскодировать личный ключ
            using (IPrivateKey privateKey = (IPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                IParameters ecParameters = (IParameters)privateKey.Parameters; 

		        // вычислить открытый ключ
		        EC.Point Q = ecParameters.Curve.Multiply(ecParameters.Generator, privateKey.D); 

                // создать объект открытого ключа 
                IPublicKey publicKey = new PublicKey(this, ecParameters, Q);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        } 
    }
}
