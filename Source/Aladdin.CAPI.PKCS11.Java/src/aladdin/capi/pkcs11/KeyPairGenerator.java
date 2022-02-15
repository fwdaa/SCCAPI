package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
public abstract class KeyPairGenerator extends aladdin.capi.KeyPairGenerator
{
	// конструктор
	protected KeyPairGenerator(Applet applet, SecurityObject scope, IRand rand) 
    { 
        // сохранить переданные параметры
        super(applet.provider(), scope, rand); 
        
        // сохранить переданные параметры
        this.applet = RefObject.addRef(applet); 
    }
    // деструктор
    @Override protected void onClose() throws IOException  
    {
        // освободить выделенные ресурсы
        RefObject.release(applet); super.onClose();
    }
	// используемое устройство
	protected final Applet applet() { return applet; } private final Applet applet; 
    
	// параметры алгоритма
	protected abstract Mechanism getParameters(Session sesssion, String keyOID); 
    
	// сгенерировать пару ключей
    @Override
	public KeyPair generate(byte[] keyID, String keyOID,  
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
    {
        // сгенерировать пару ключей
        if (!(scope() instanceof Container)) return generate(keyOID, keyUsage);
        
        // выполнить преобразование типа
        Container container = (Container)scope(); String name = container.name().toString();
        
        // создать списки атрибутов
        List<Attribute> pubAttributes  = new ArrayList<Attribute>(
            Arrays.asList(getPublicAttributes(keyOID))
        ); 
        List<Attribute> privAttributes = new ArrayList<Attribute>(
            Arrays.asList(getPrivateAttributes(keyOID))
        ); 
        // указать принадлежность токену
        pubAttributes .add(new Attribute(API.CKA_TOKEN  , API.CK_TRUE));
        privAttributes.add(new Attribute(API.CKA_TOKEN  , API.CK_TRUE));
        privAttributes.add(new Attribute(API.CKA_PRIVATE, API.CK_TRUE));

        // указать имя контейнера
        pubAttributes .add(new Attribute(API.CKA_LABEL, name.getBytes("UTF-8")));
        privAttributes.add(new Attribute(API.CKA_LABEL, name.getBytes("UTF-8")));

        // проверить возможность экспорта
        byte exportable = (keyFlags.equals(KeyFlags.EXPORTABLE)) ? API.CK_TRUE : API.CK_FALSE; 
            
        // указать признак извлекаемости ключа
        privAttributes.add(new Attribute(API.CKA_EXTRACTABLE, exportable));
        
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RW_USER_FUNCTIONS)) 
        {
            // подготовится к генерации ключевой пары
            keyID = applet.prepareKeyPair(session, name, keyID, rand(), keyUsage); 
            
            // указать идентификатор ключей
            pubAttributes .add(new Attribute(API.CKA_ID, keyID)); 
            privAttributes.add(new Attribute(API.CKA_ID, keyID)); 

            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, keyOID);
            
            // сгенерировать пару ключей
            SessionObject[] sessionKeys = session.generateKeyPair(parameters, keyUsage, 
                pubAttributes .toArray(new Attribute[pubAttributes .size()]), 
                privAttributes.toArray(new Attribute[privAttributes.size()])
            );
            try { 
                // преобразовать объект открытого ключа
                IPublicKey publicKey = applet.provider().convertPublicKey(
                    applet, sessionKeys[0]
                ); 
                // проверить поддержку ключа
                if (publicKey == null) throw new UnsupportedOperationException(); 

                // преобразовать объект личного ключа
                try (IPrivateKey privateKey = applet.provider().convertPrivateKey(
                    container, sessionKeys[1], publicKey))
                {
                    // проверить поддержку ключа
                    if (privateKey == null) throw new UnsupportedOperationException(); 

                    // вернуть созданную пару ключей
                    return new KeyPair(publicKey, privateKey, keyID); 
                }
            }
            catch (IOException e)
            {
                // удалить открытый и личный ключ
                session.destroyObject(sessionKeys[0]); 
                session.destroyObject(sessionKeys[1]); throw e; 
            }
        }
    }
	// сгенерировать пару ключей
	public KeyPair generate(String keyOID, KeyUsage keyUsage) throws IOException
    {
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // сгенерировать пару ключей
            SessionObject[] sessionKeys = generate(session, keyOID, keyUsage); 
            try { 
                // преобразовать объект открытого ключа
                IPublicKey publicKey = applet.provider().convertPublicKey(
                    applet, sessionKeys[0]
                ); 
                // проверить поддержку ключа
                if (publicKey == null) throw new UnsupportedOperationException(); 

                // преобразовать объект личного ключа
                try (IPrivateKey privateKey = applet.provider().convertPrivateKey(
                    scope(), sessionKeys[1], publicKey)) 
                {
                    // проверить поддержку ключа
                    if (privateKey == null) throw new UnsupportedOperationException(); 

                    // вернуть созданную пару ключей
                    return new KeyPair(publicKey, privateKey, null); 
                }
            }
            finally {
                // удалить открытый и личный ключ
                session.destroyObject(sessionKeys[0]); 
                session.destroyObject(sessionKeys[1]);
            }
        }
    }
	// сгенерировать пару ключей
	public SessionObject[] generate(Session session, 
        String keyOID, KeyUsage keyUsage) throws IOException
    {
        // создать списки атрибутов
        List<Attribute> pubAttributes  = new ArrayList<Attribute>(
            Arrays.asList(getPublicAttributes(keyOID))
        ); 
        List<Attribute> privAttributes = new ArrayList<Attribute>(
            Arrays.asList(getPrivateAttributes(keyOID))
        ); 
        // указать принадлежность токену
        pubAttributes .add(new Attribute(API.CKA_TOKEN  , API.CK_FALSE));
        privAttributes.add(new Attribute(API.CKA_TOKEN  , API.CK_FALSE));
        privAttributes.add(new Attribute(API.CKA_PRIVATE, API.CK_FALSE));

        // получить параметры алгоритма
        Mechanism parameters = getParameters(session, keyOID);
            
        // сгенерировать пару ключей
        return session.generateKeyPair(parameters, keyUsage, 
            pubAttributes .toArray(new Attribute[pubAttributes .size()]), 
            privAttributes.toArray(new Attribute[privAttributes.size()])
        ); 
    }
	// атрибуты открытого ключа
	protected abstract Attribute[] getPublicAttributes (String keyOID);
	// атрибуты личного ключа
	protected Attribute[] getPrivateAttributes(String keyOID) { return new Attribute[0]; }
};
