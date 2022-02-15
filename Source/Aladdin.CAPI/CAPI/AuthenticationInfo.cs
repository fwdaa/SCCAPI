using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация аутентификации
    ///////////////////////////////////////////////////////////////////////////
    public class AuthenticationInfo
    {
        // неограниченное число попыток
        public const int UnlimitedAttempts = Int32.MaxValue; 
        // неограниченное число попыток
        public const int UnknownAttempts = -1; 

        // максимальное/текущее число попыток аутентификации
        private int maximumAttemps; private int currentAttemps; 

        // конструктор
        public AuthenticationInfo() : this(UnknownAttempts) {}
        // конструктор
        public AuthenticationInfo(int maximumAttemps) : this(maximumAttemps, UnknownAttempts) {}
        // конструктор
        public AuthenticationInfo(int maximumAttemps, int currentAttemps)
        {
            // сохранить переданные параметры
            this.maximumAttemps = maximumAttemps; this.currentAttemps = currentAttemps; 
        }
        // максимальное/текущее число попыток аутентификации
        public int MaximumLoginAttempts { get { return maximumAttemps; }} 
        public int CurrentLoginAttempts { get { return currentAttemps; }} 

        // признак блокировки аутентификации
        public bool IsLocked { get 
        {
            // получить максимальное число попыток аутентификации
            int attemptsMax = MaximumLoginAttempts; 

            // проверить неизвестное число попыток
            if (attemptsMax == UnknownAttempts) return false;

            // проверить неограниченное число попыток
            if (attemptsMax == UnlimitedAttempts) return false;

            // получить текущее число попыток аутентификации
            int attemptsCurrent = CurrentLoginAttempts; 

            // проверить неизвестное число попыток
            if (attemptsCurrent == UnknownAttempts) return false;

            // вернуть признак блокировки аутентификации
            return (attemptsMax == attemptsCurrent); 
        }}
    }
}
