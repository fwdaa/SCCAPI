package aladdin.capi.pkcs12;
import aladdin.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Зашифрованный на открытом ключ контейнер PKCS12 с имитовставкой
///////////////////////////////////////////////////////////////////////////
public class PfxAuthenticatedEncryptedContainer 
    extends PfxEncryptedContainer implements IPfxAuthenticatedContainer 
{
    // пароль проверки целостности
    private String password;
    
	// конструктор
	public PfxAuthenticatedEncryptedContainer(PFX content, Factory factory, IRand rand) throws IOException
    { 
		// сохранить переданные параметры
		super(content, factory, rand); this.password = null; 
    } 
    // пароль проверки целостности
    @Override public final String authenticationPassword() { return password; }
    
	// установить ключи
	@Override public void setAuthenticationPassword(String password) throws IOException
	{
        // проверить корректность имитовставки
        Pfx.checkAuthenticatedContainer(factory(), content, password);
        
		// сохранить переданный пароль
		this.password = password;  
	}
    // изменить пароль проверки целостности
	@Override public void changeAuthenticationPassword(String password) throws IOException
	{
        // проверить наличие пароля
        if (this.password == null) throw new AuthenticationException(); 

        // сохранить переданный пароль
		String oldPassword = this.password; this.password = password;

        // изменить пароль
        try { change(); } catch (IOException e) { this.password = oldPassword; throw e; }
    }
	// указать пароль 
	public final void setPassword(String password) throws IOException
	{
        // создать ключ
        ISecretKey key = SecretKey.fromPassword(password, "UTF-8");  
        
		// указать пароль проверки целостности и ключ шифрования
        setAuthenticationPassword(password); setEncryptionKey(key);
	}
    // изменить пароль 
	public final void changePassword(String password) throws IOException
	{
        // проверить наличие пароля
        if (this.password == null) throw new AuthenticationException(); 
        
        // создать новый ключ шифрования
        ISecretKey key = SecretKey.fromPassword(password, "UTF-8");  
            
        // сохранить старый ключ шифрования
        try (ISecretKey oldKey = RefObject.addRef(encryptionKey())) 
        { 
            // изменить ключ шифрования и пароль проверки целостности
            changeEncryptionKey(key); try { changeAuthenticationPassword(password); }

            // при ошибке восстановить старый ключ шифрования
            catch (IOException e) { changeEncryptionKey(oldKey); throw e; }
        }
    }
	@Override protected void onChange(AuthenticatedSafe authenticatedSafe) throws IOException
	{
		// проверить наличие пароля
		if (password == null) throw new AuthenticationException();

		// выделить память для salt-значения
		byte[] salt = new byte[content.macData().macSalt().value().length]; 

        // сгенерировать salt-значение
        rand().generate(salt, 0, salt.length); 
        
		// получить число итераций
		int iterations = content.macData().iterations().value().intValue(); 

        // закодировать контейнер
		content = Pfx.createAuthenticatedContainer(factory(), authenticatedSafe, 
           content.macData().mac().digestAlgorithm(), salt, iterations, password
        ); 
	}
}
