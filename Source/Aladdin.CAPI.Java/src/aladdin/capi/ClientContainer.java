package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkix.ce.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Контейнер
///////////////////////////////////////////////////////////////////////////
public class ClientContainer extends RefObject implements IClient
{
    // криптографический провайдер и информация о контейнере
    private final CryptoProvider provider; private final SecurityInfo info;
    // способ выбора аутентификации
    private final AuthenticationSelector selector;

    // конструктор
    public ClientContainer(CryptoProvider provider, SecurityInfo info, AuthenticationSelector selector)
    {
        // сохранить переданные параметры
        this.provider = RefObject.addRef(provider); this.info = info;

        // указать значение селектора по умолчанию
        this.selector = (selector != null) ? selector : new AuthenticationSelector("USER");
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(provider); super.onClose(); 
    }
    // криптографический провайдер
    public final CryptoProvider provider() { return provider; }
    // информация контейнера
    public final SecurityInfo info() { return info; }

    ///////////////////////////////////////////////////////////////////////
    // Уникальный идентификатор
    ///////////////////////////////////////////////////////////////////////
    @Override public String getUniqueID() throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // получить уникальный идентификатор
            return container.getUniqueID(); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Генератор случайных данных
    ///////////////////////////////////////////////////////////////////////
    public IRand createRand() throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // создать генератор случайных данных
            return selector.createRand(provider, container); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Открытые ключи контейнера
    ///////////////////////////////////////////////////////////////////////
    public IPublicKey getPublicKey(byte[] keyID) throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // получить открытый ключ из контейнера
            return container.getPublicKey(keyID);
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Личные ключи контейнера
    ///////////////////////////////////////////////////////////////////////
    @Override public byte[] getPrivateKey(
        Certificate certificate, Attributes attributes) throws IOException
    {
        // открыть контейнер
		try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
		{
            // закодировать личный ключ
            return container.getPrivateKey(certificate, attributes); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Сертификаты контейнера
    ///////////////////////////////////////////////////////////////////////
    public Certificate[] enumerateAllCertificates() throws IOException
    { 
 	    // открыть контейнер
	    try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
	    {
            // перечислить сертификаты
            return container.enumerateAllCertificates();         
        }
    }
    @Override public Certificate[] enumerateCertificates() throws IOException
    { 
    	// открыть контейнер
		try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
		{
            // перечислить сертификаты контейнера
            return container.enumerateCertificates(); 
        }
    }
    public Certificate getCertificate(byte[] keyID) throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // получить сертификат из контейнера
            return container.getCertificate(keyID);
        }
    }
    public Certificate[] getCertificateChain(Certificate certificate) throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // получить цепочку сертификатов из контейнера
            return container.getCertificateChain(certificate);
        }
    }
    public void setCertificateChain(byte[] keyID, Certificate[] certificateChain) throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "rw"))
        {
            // получить открытый ключ
            IPublicKey publicKey = container.getPublicKey(keyID); 
        
            // проверить наличие ключа
            if (publicKey == null) throw new NoSuchElementException(); 

            // закодировать открытый ключ
            SubjectPublicKeyInfo keyInfo = publicKey.encoded(); 

            // проверить совпадение открытых ключей
            if (!certificateChain[0].publicKeyInfo().equals(keyInfo)) throw new IOException();
            
            // записать сертификат в контейнер
            container.setCertificateChain(keyID, certificateChain);
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Ключевые пары контейнера
    ///////////////////////////////////////////////////////////////////////
    public ContainerKeyPair[] enumerateKeyPairs() throws IOException
    {
        // выделить память для пар ключей
        List<ContainerKeyPair> keyPairs = new ArrayList<ContainerKeyPair>();

        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // для всех ключей
            for (byte[] id : container.getKeyIDs())
            try {
                // получить сертификат
                Certificate certificate = container.getCertificate(id); String keyOID;

                // указать идентификатор ключа
                if (certificate == null) { keyOID = container.getPublicKey(id).keyOID();
                
                    // добавить пару ключей в список
                    keyPairs.add(new ContainerKeyPair(info, id, keyOID, null));
                }
                else { 
                    // указать идентификатор ключа
                    keyOID = certificate.publicKeyInfo().algorithm().algorithm().value();
                    
                    // получить цепь сертификатов
                    Certificate[] certificateChain = container.getCertificateChain(certificate); 
                    
                    // добавить пару ключей в список
                    keyPairs.add(new ContainerKeyPair(info, id, keyOID, certificateChain));
                }
            }
            // вернуть описание ключей
            catch (Throwable e) {} return keyPairs.toArray(new ContainerKeyPair[0]);
        }
    }
    public ContainerKeyPair getKeyPair(Certificate certificate) throws IOException
    {
        // определить идентификатор ключа
        String keyOID = certificate.publicKeyInfo().algorithm().algorithm().value(); 

        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // найти ключевую пару для сертификата
            byte[] id = container.getKeyPair(certificate); 

            // проверить наличие ключевой пары
            if (id == null) return null; 
            
            // получить цепь сертификатов 
            Certificate[] certificateChain = 
                container.getCertificateChain(certificate); 

            // вернуть найденную ключевую пару
            return new ContainerKeyPair(info, id, keyOID, certificateChain); 
        }
    }
    public void deleteKeyPair(byte[] keyID) throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "rw"))
        {
            // удалить ключевую пару контейнера
            container.deleteKeyPair(keyID);
        }
    }
    ///////////////////////////////////////////////////////////////////////
	// Сгенерировать пару ключей
	///////////////////////////////////////////////////////////////////////
    public ContainerKeyPair generateKeyPair(IRand rand, IParametersFactory factory, 
        String keyOID, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "rw")) 
        { 
            // указать генератор случайных данных
            try (IRand rebindRand = selector.rebindRand(rand))
            { 
                // выбрать параметры алгоритма
                IParameters keyParameters = factory.getParameters(rebindRand, keyOID, keyUsage); 

                // сгенерировать ключи в контейнере
                try (KeyPair keyPair = container.generateKeyPair(
                    rebindRand, null, keyOID, keyParameters, keyUsage, keyFlags)) 
                { 
                    // закрыть контейнер
                    return new ContainerKeyPair(info, keyPair.keyID, keyOID, null);
                }
            }
        }
	}
	///////////////////////////////////////////////////////////////////////
	// Импортировать/экспортировать пару ключей
	///////////////////////////////////////////////////////////////////////
	public ContainerKeyPair importKeyPair(IRand rand, IPublicKey publicKey, 
        IPrivateKey privateKey, Certificate[] certificateChain, 
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
    {
        // открыть исходный контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "rw"))
        { 
            // указать генератор случайных данных
            try (IRand rebindRand = selector.rebindRand(rand))
            { 
  	            // импортировать ключи в контейнер
	            try (KeyPair keyPair = container.importKeyPair(rebindRand, publicKey, privateKey, keyUsage, keyFlags)) 
                { 
                    // записать сертификат в контейнер
                    if (certificateChain != null) container.setCertificateChain(keyPair.keyID, certificateChain);
                            
                    // вернуть описание пары ключей контейнера
                    return new ContainerKeyPair(info, keyPair.keyID, publicKey.keyOID(), certificateChain); 
                }
            }
        }
    }
    public ContainerKeyPair exportKeyPair(byte[] keyID, 
        CryptoProvider providerTo, SecurityInfo infoTo, 
        IRand rand, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // открыть исходный контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        { 
            // получить открытый ключ
            IPublicKey publicKey = container.getPublicKey(keyID);

            // проверить наличие ключа
            if (publicKey == null) throw new NoSuchElementException();

            // получить сертификат
            Certificate certificate = container.getCertificate(keyID);
            
            // при наличии сертификата 
            Certificate[] certificateChain = null; if (certificate != null)
            {
                // получить цепь сертификатов
                certificateChain = container.getCertificateChain(certificate); 
            }
            // получить личный ключ
            try (IPrivateKey privateKey = container.getPrivateKey(keyID))
            {
                // указать другой контейнер
                try (ClientContainer containerTo = new ClientContainer(providerTo, infoTo, selector))
                { 
                    // импортировать пару ключей
                    return containerTo.importKeyPair(rand, 
                        publicKey, privateKey, certificateChain, keyUsage, keyFlags
                    ); 
                }
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////
	// Создать самоподписанный сертификат
	///////////////////////////////////////////////////////////////////////
    public Certificate createSelfSignedCertificate(IRand rand, 
        byte[] keyID, IEncodable subject, Date notBefore, Date notAfter, 
        AlgorithmIdentifier signParameters, KeyUsage keyUsage, 
        String[] extKeyUsages, BasicConstraints basicConstraints, 
        CertificatePolicies policies, Extensions extensions) throws IOException
    {
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "rw")) 
        {
            // получить открытый ключ
            IPublicKey publicKey = container.getPublicKey(keyID); 

            // проверить наличие ключа
            if (publicKey == null) throw new NoSuchElementException(); 
            
		    // получить личный ключ
		    try (IPrivateKey privateKey = container.getPrivateKey(keyID)) 
            {
                // указать генератор случайных данных
                try (IRand rebindRand = selector.rebindRand(rand))
                {
                    // создать самоподписанный сертификат
                    Certificate certificate = PKI.createSelfSignedCertificate(
                        rebindRand, subject, signParameters, publicKey, privateKey, 
                        notBefore, notAfter, keyUsage, extKeyUsages, 
                        basicConstraints, policies, extensions
                    ); 
                    // создать цепь сертификатов
                    Certificate[] certificateChain = new Certificate[] {certificate}; 
                    
                    // записать сертификат в контейнер
                    container.setCertificateChain(keyID, certificateChain); return certificate; 
                }
            }
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Создать запрос на сертификат
	///////////////////////////////////////////////////////////////////////
	public CertificateRequest createCertificateRequest(
        IRand rand, byte[] keyID, IEncodable subject, 
        AlgorithmIdentifier signParameters, Extensions extensions) throws IOException
	{
        // открыть контейнер
        try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
        {
            // получить открытый ключ
            IPublicKey publicKey = container.getPublicKey(keyID); 

            // проверить наличие ключа
            if (publicKey == null) throw new NoSuchElementException(); 

     	    // получить личный ключ
		    try (IPrivateKey privateKey = container.getPrivateKey(keyID)) 
            {
                // указать генератор случайных данных
                try (IRand rebindRand = selector.rebindRand(rand))
                {
                    // сгенерировать запрос на сертификат
                    return PKI.createCertificationRequest(rebindRand, 
                        subject, signParameters, publicKey, privateKey, extensions
                    );
                }
            }
		}
    }
    ///////////////////////////////////////////////////////////////////////
    // Выполнение криптографических операций
    ///////////////////////////////////////////////////////////////////////
    @Override public byte[] encryptData(IRand rand, Culture culture, 
        Certificate certificate, Certificate[] recipientCertificates, 
        CMSData data, Attributes attributes) throws IOException
    {
        // открыть контейнер
		try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
		{
            // указать генератор случайных данных
            try (IRand rebindRand = selector.rebindRand(rand))
            {
                // зашифровать данные
                return container.encryptData(rebindRand, culture, 
                    certificate, recipientCertificates, data, attributes
                ); 
            }
        }
    }
	@Override public CMSData decryptData(byte[] contentInfo) throws IOException
    {
		// открыть контейнер
		try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
		{
            // расшифровать данные
            return container.decryptData(contentInfo);
        }
    }
    @Override public byte[] signData(IRand rand, Culture culture, 
        Certificate certificate, CMSData data, 
        Attributes[] authAttributes, Attributes[] unauthAttributes) throws IOException
    {
    	// открыть контейнер
		try (Container container = (Container)selector.openObject(
            provider, info.scope, info.fullName(), "r"))
		{
            // указать генератор случайных данных
            try (IRand rebindRand = selector.rebindRand(rand))
            {
                // подписать данные
                return container.signData(rebindRand, culture, 
                    certificate, data, authAttributes, unauthAttributes
                );
            }
        }
    }
}
