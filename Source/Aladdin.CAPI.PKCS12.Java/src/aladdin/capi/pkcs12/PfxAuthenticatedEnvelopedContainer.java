package aladdin.capi.pkcs12;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Зашифрованный на открытом ключ контейнер PKCS12 с имитовставкой
///////////////////////////////////////////////////////////////////////////
public class PfxAuthenticatedEnvelopedContainer 
    extends PfxEnvelopedContainer implements IPfxAuthenticatedContainer
{
    // фабрика алгоритмов и пароль проверки целостности
    private final Factory factory; private String password;

	// конструктор
	public PfxAuthenticatedEnvelopedContainer(PFX content, Factory factory, IRand rand) throws IOException
    {
        // сохранить переданные параметры
        super(content, rand); this.factory = RefObject.addRef(factory); password = null; 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
		RefObject.release(factory); super.onClose();
    }
    // фабрика алгоритмов
    @Override public final Factory factory() { return factory; }
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
	@Override public final void changeAuthenticationPassword(String password) throws IOException
	{
        // проверить наличие пароля
        if (this.password == null) throw new AuthenticationException(); 

        // сохранить переданный пароль
		String oldPassword = this.password; this.password = password;

        // изменить пароль
        try { change(); } catch (IOException e) { this.password = oldPassword; throw e; }
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
