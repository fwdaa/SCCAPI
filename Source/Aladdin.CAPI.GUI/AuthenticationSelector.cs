using System;
using System.Windows.Forms;
using System.Collections.Generic;

namespace Aladdin.CAPI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Определение способа аутентификации
    ///////////////////////////////////////////////////////////////////////////
    public class AuthenticationSelector : CAPI.AuthenticationSelector
    {
        // указать способ выбора аутентификации
        public static AuthenticationSelector Create(IWin32Window window)
        {
            // указать способ выбора аутентификации
            return new AuthenticationSelector(window, "USER");
        }
        // конструктор
        public AuthenticationSelector(IWin32Window window, string user) 
             
            // сохранить переданные параметры
            : base(user) { this.window = window; } private IWin32Window window; 

        ///////////////////////////////////////////////////////////////////////
		// Создать генератор случайных данных
		///////////////////////////////////////////////////////////////////////
        public override IRand CreateRand(CryptoProvider provider, SecurityObject container)
        {
		    // создать генератор случайных данных
            return provider.CreateRand(container, window); 
        }
        // указать другое графическое окружение
        public override IRand RebindRand(IRand rand) { return Rand.Rebind(rand, window); }

        ///////////////////////////////////////////////////////////////////////
        // Отобразить диалог
        ///////////////////////////////////////////////////////////////////////
		public override SecurityObject ShowCreate(
            CryptoProvider provider, SecurityInfo info, IRand rand, 
            List<Type> authenticationTypes, params object[] parameters)
        {
            // проверить указание типов аутентификации
            if (authenticationTypes.Count == 0) return null; 

            // проверить поддержку нескольких аутентификаций
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials )) && 
                authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // операция не реализована
                throw new NotImplementedException(); 
            }
            // для парольной аутентификации
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials)))
            {
                // создать объект с парольной аутентификацией
                return PasswordChangeDialog.ShowCreate(
                    window, provider, info, rand, User, parameters
                ); 
            }
            // для биометрической аутентификации
            if (authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // операция не реализована
                throw new NotImplementedException(); 
            }
            return null; 
        }
		public Credentials[] Show(SecurityObject obj, List<Type> authenticationTypes)
        {
            // проверить указание типов аутентификации
            if (authenticationTypes.Count == 0) return new Credentials[0]; 

            // проверить поддержку нескольких аутентификаций
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials )) && 
                authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // показать диалог биометрической аутентификации с паролем
                return BioPinMatchDialog.Show(window, obj, User);
            }
            // для парольной аутентификации
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials)))
            {
                // показать диалог парольной аутентификации
                return PasswordDialog.Show(window, obj, User); 
            }
            // для биометрической аутентификации
            if (authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // показать диалог биометрической аутентификации
                return BioMatchDialog.Show(window, obj, User); 
            }
            return null; 
        }
		public void ShowChange(SecurityObject obj, List<Type> authenticationTypes)
        {
            // проверить указание типов аутентификации
            if (authenticationTypes.Count == 0) return; 

            // проверить поддержку нескольких аутентификаций
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials )) && 
                authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // изменить биометрическую и парольную аутентификацию
                BioPinEnrollDialog.ShowChange(window, obj, User); return; 
            }
            // для парольной аутентификации
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials)))
            {
                // изменить парольную аутентификацию
                PasswordChangeDialog.ShowChange(window, obj, User); return; 
            }
            // для биометрической аутентификации
            if (authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // изменить биометрическую аутентификацию
                BioEnrollDialog.ShowChange(window, obj, User); return; 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Способ аутентификации
        ///////////////////////////////////////////////////////////////////////
        protected override Authentication[] GetAuthentications(
            SecurityObject obj, List<Type> authenticationTypes)
        { 
            // проверить наличие аутентификаций
            if (authenticationTypes.Count == 0) return new Authentication[0]; 

            // проверить поддержку нескольких аутентификаций
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials )) && 
                authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // указать используемую аутентификацию
                return new Authentication[] {new AuthenticationDialog.Authentication(window, User)}; 
            }
            // для парольной аутентификации
            if (authenticationTypes.Contains(typeof(Auth.PasswordCredentials)))
            {
                // указать используемую аутентификацию
                return new Authentication[] {new PasswordDialog.Authentication(window, User)}; 
            }
            // для биометрической аутентификации
            if (authenticationTypes.Contains(typeof(Auth.BiometricCredentials)))
            {
                // указать используемую аутентификацию
                return new Authentication[] {new BioMatchDialog.Authentication(window, User)}; 
            }
            // вызвать базовую функцию
            return base.GetAuthentications(obj, authenticationTypes);
        }
        ///////////////////////////////////////////////////////////////////////
        // Открыть или создать контейнер
        ///////////////////////////////////////////////////////////////////////
        public static Container OpenOrCreate(IWin32Window window, 
            CryptoProvider provider, SecurityInfo info, params object[] parameters)
        {
            // указать способ выбора аутентификации
            AuthenticationSelector selector = Create(window); 

            // открыть или создать контейнер
            return selector.OpenOrCreate(provider, info, parameters); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Удалить контейнер
        ///////////////////////////////////////////////////////////////////////
        public static void Delete(IWin32Window window, IProvider provider, SecurityInfo info)
        {
            // указать способ выбора аутентификации
            AuthenticationSelector selector = Create(window);

            // удалить контейнер
            selector.DeleteObject(provider, info.Scope, info.FullName); 
        }
    }
}
