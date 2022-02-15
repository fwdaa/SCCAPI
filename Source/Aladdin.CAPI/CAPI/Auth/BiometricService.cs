using System;

namespace Aladdin.CAPI.Auth
{
    ///////////////////////////////////////////////////////////////////////////
    // Сервис биометрической аутентификации
    ///////////////////////////////////////////////////////////////////////////
    public abstract class BiometricService : AuthenticationService
    {
        // конструктор
        public BiometricService(SecurityObject obj, string user) : base(obj, user) {}

        // используемый провайдер
        public abstract Bio.Provider Provider { get; } 
        
        // максимальное число отпечатков
        public virtual int GetMaxAvailableFingers() { throw new NotSupportedException(); }
        // доступные отпечатки
        public abstract Bio.Finger[] GetAvailableFingers();

		// получить шаблон для проверки отпечатка
        public abstract Bio.MatchTemplate CreateTemplate(Bio.Finger finger, Bio.Image image); 

		// проверить соответствие отпечатка
        public Credentials Match(Bio.MatchTemplate matchTemplate)
        {
            // проверить соответствие отпечатка
            matchTemplate = MatchTemplate(matchTemplate); string provider = Target.Provider.Name; 
        
            // указать тип аутентификации
            Credentials credentials = new BiometricCredentials(User, matchTemplate); 

            // получить кэш аутентификации
            CredentialsManager credentialsManager = ExecutionContext.GetProviderCache(provider);

            // добавить данные в кэш
            credentialsManager.SetData(Target.Info, User, credentials); return credentials; 
        }
		// проверить соответствие отпечатка
        protected virtual Bio.MatchTemplate MatchTemplate(Bio.MatchTemplate matchTemplate)
        {
            // операция не поддерживается
            throw new NotSupportedException(); 
        }
        // установить отпечатки
        public void Enroll(Bio.EnrollTemplate[] enrollTemplates)
        {
            // установить отпечатки
            EnrollTemplates(enrollTemplates); string provider = Target.Provider.Name; 
        
            // получить кэш аутентификации
            CredentialsManager credentialsManager = ExecutionContext.GetProviderCache(provider);

            // удалить данные из кэша
            credentialsManager.ClearData(Target.Info, User, typeof(BiometricCredentials)); 
        }
        // установить отпечатки
        protected virtual void EnrollTemplates(Bio.EnrollTemplate[] enrollTemplates)
        {
            // операция не поддерживается
            throw new NotSupportedException(); 
        }
    }
}
