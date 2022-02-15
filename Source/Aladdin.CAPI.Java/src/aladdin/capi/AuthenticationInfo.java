package aladdin.capi;

///////////////////////////////////////////////////////////////////////////
// Информация аутентификации
///////////////////////////////////////////////////////////////////////////
public class AuthenticationInfo
{
    // неограниченное число попыток
    public final static int UNLIMITED_ATTEMPTS = Integer.MAX_VALUE; 
    // неограниченное число попыток
    public final static int UNKNOWN_ATTEMPTS = -1; 

    // максимальное/текущее число попыток аутентификации
    private final int maximumAttemps; private final int currentAttemps; 

    // конструктор
    public AuthenticationInfo() { this(UNKNOWN_ATTEMPTS); }
    // конструктор
    public AuthenticationInfo(int maximumAttemps) 
    { 
        // сохранить переданные параметры
        this(maximumAttemps, UNKNOWN_ATTEMPTS); 
    }
    // конструктор
    public AuthenticationInfo(int maximumAttemps, int currentAttemps)
    {
        // сохранить переданные параметры
        this.maximumAttemps = maximumAttemps; this.currentAttemps = currentAttemps; 
    }
    // максимальное/текущее число попыток аутентификации
    public int maximumLoginAttempts() { return maximumAttemps; } 
    public int currentLoginAttempts() { return currentAttemps; } 

    // признак блокировки аутентификации
    public boolean isLocked() 
    {
        // получить максимальное число попыток аутентификации
        int attemptsMax = maximumLoginAttempts(); 

        // проверить неизвестное число попыток
        if (attemptsMax == UNKNOWN_ATTEMPTS) return false;

        // проверить неограниченное число попыток
        if (attemptsMax == UNLIMITED_ATTEMPTS) return false;

        // получить текущее число попыток аутентификации
        int attemptsCurrent = currentLoginAttempts(); 

        // проверить неизвестное число попыток
        if (attemptsCurrent == UNKNOWN_ATTEMPTS) return false;

        // вернуть признак блокировки аутентификации
        return (attemptsMax == attemptsCurrent); 
    }
}
