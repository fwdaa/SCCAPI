package aladdin.capi.pkcs12;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Контейнер PKCS12 с имитовставкой
///////////////////////////////////////////////////////////////////////////
public interface IPfxAuthenticatedContainer
{
    // фабрика алгоритмов и пароль проверки целостности
    Factory factory(); String authenticationPassword();

    // указать пароль проверки целостности
	void setAuthenticationPassword(String password) throws IOException; 

    // изменить пароль проверки целостности
	void changeAuthenticationPassword(String password) throws IOException; 
}
