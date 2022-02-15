using System;
using System.IO;
using System.Windows.Forms;
using System.Collections.Generic;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище криптографического провайдера
	///////////////////////////////////////////////////////////////////////////
	internal class StoreNode : ConsoleForm.Node
	{
		private CryptoEnvironment  environment; // криптографическая среда
		private CryptoProvider     provider;	// криптографический провайдер
        private Type               storeType;   // тип хранилища контейнеров
		private SecurityInfo       storeInfo;   // информация хранилища
		
		// конструктор
		public StoreNode(CryptoEnvironment environment, 
            CryptoProvider provider, Type storeType, SecurityInfo storeInfo) 
		{ 
			// сохранить переданные данные
			this.environment = environment; this.provider = provider; 
            
			// сохранить переданные данные
            this.storeType = storeType; this.storeInfo = storeInfo; 
		} 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Store.ico"; }
		// значение узла
		public override string Label { get { return storeInfo.Name.ToString(); }}

		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 
		// признак допустимости удаления 
		public override bool CanDelete { get { 

            // признак допустимости удаления 
            return typeof(Software.DirectoryStore).IsAssignableFrom(storeType); 
        }}
		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
			// создать список дочерних элементов
			List<ConsoleForm.Node> nodes = new List<ConsoleForm.Node>();
            try { 
                // указать способ выбора аутентификации 
                AuthenticationSelector selector = AuthenticationSelector.Create(node.MainForm); 

                // открыть хранилище объектов
                using (SecurityStore store = (SecurityStore)selector.OpenObject(
                    provider, storeInfo.Scope, storeInfo.FullName, FileAccess.Read))
                {
			        // для каждого дочернего объекта
			        foreach (string name in store.EnumerateObjects())
			        {
                        // для хранилища контейнеров
                        if (typeof(ContainerStore).IsAssignableFrom(storeType))
                        {
                            // указать информацию контейнера
                            SecurityInfo containerInfo = new SecurityInfo(storeInfo.Scope, storeInfo.FullName, name); 

        	                // добавить дочерний узел
			                nodes.Add(new ContainerNode(environment, provider, storeType, storeInfo, containerInfo));
                        }
                        // открыть объект
                        else using (SecurityObject obj = store.OpenObject(name, FileAccess.Read))
                        {
				            // добавить дочерний узел
				            nodes.Add(new StoreNode(environment, provider, obj.GetType(), obj.Info)); 
                        }
			        }
                }
            }
            // вернуть список узлов
			catch {} return nodes.ToArray(); 
		}
		// элементы контекстного меню для узла
		public override ToolStripItem[] GetContextMenuItems(ConsoleNode node) 
		{ 
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; bool canChangeLongin = false; 

            // указать способ выбора аутентификации 
            AuthenticationSelector selector = AuthenticationSelector.Create(mainForm);
            try { 
                // открыть хранилище объектов
                using (SecurityStore store = (SecurityStore)selector.OpenObject(
                    provider, storeInfo.Scope, storeInfo.FullName, FileAccess.Read))
                { 
                    // для всех поддерживаемых типов аутентификации
                    foreach (Type authenticationType in store.GetAuthenticationTypes(selector.User))
                    {
                        // получить сервис аутентификации
                        AuthenticationService service = store.GetAuthenticationService(
                            selector.User, authenticationType
                        ); 
                        // добавить тип используемой аутентификации
                        if (service.CanChange) { canChangeLongin = true; break; }
                    }
                }
            }
			// список элементов меню 
			catch {} List<ToolStripItem> items = new List<ToolStripItem>(); 
            
            // для хранилища контейнеров
            if (typeof(ContainerStore).IsAssignableFrom(storeType))
            { 
			    // добавить элемент меню
			    items.Add(new ToolStripMenuItem(Resource.MenuGenerateKeyPair, null, 
				    delegate (object sender, EventArgs e) { OnGenerateKeyPair(node, sender, e); }
			    )); 
			    // добавить элемент меню
			    items.Add(new ToolStripMenuItem(Resource.MenuImportKeyPair, null, 
				    delegate (object sender, EventArgs e) { OnImportKeyPair(node, sender, e); }
			    )); 
            }
            if (canChangeLongin) 
            { 
				// при необходимости указать разделитель
                if (items.Count > 0) items.Add(new ToolStripSeparator());

				// добавить элемент меню
                items.Add(new ToolStripMenuItem(Resource.MenuChangeLogin, null, 
				    delegate (object sender, EventArgs e) { OnChangeLogin(node, sender, e); }
			    ));
            }
            // для набора каталогов
            if (typeof(Software.DirectoriesStore).IsAssignableFrom(storeType))
            {
				// при необходимости указать разделитель
                if (items.Count > 0) items.Add(new ToolStripSeparator());

				// добавить элемент меню
				items.Add(new ToolStripMenuItem(Resource.MenuManageDirectories, null, 
					delegate (object sender, EventArgs e) { OnManageDirectories(node, sender, e); }
				)); 
            }
            // для провайдера PKCS11
            if (provider is CAPI.PKCS11.Provider)
            {
				// при необходимости указать разделитель
                if (items.Count > 0) items.Add(new ToolStripSeparator());

				// добавить элемент меню
				items.Add(new ToolStripMenuItem(Resource.MenuProperties, null, 
					delegate (object sender, EventArgs e) { OnProperty(node, sender, e); }
				)); 
            }
            return items.ToArray(); 
		}
		// обработать двойное нажатие
		public override void OnProperty(ConsoleNode node, object sender, EventArgs e) 
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

            // указать способ выбора аутентификации 
            AuthenticationSelector selector = AuthenticationSelector.Create(mainForm);
            try { 
                // открыть хранилище объектов
                using (SecurityStore store = (SecurityStore)selector.OpenObject(
                    provider, storeInfo.Scope, storeInfo.FullName, FileAccess.Read))
                {
                    // проверить тип хранилища
                    if (store is CAPI.PKCS11.Applet)
                    {
                        // выполнить преобразование типа
                        CAPI.PKCS11.Applet applet = (CAPI.PKCS11.Applet)store; 

			            // создать диалог свойств
			            AppletDialog dialog = new AppletDialog(applet); 

			            // показать диалог импорта
			            dialog.ShowDialog(mainForm); 
                    }
                    else if (store is CAPI.PKCS11.Token)
                    {
                        // выполнить преобразование типа
                        CAPI.PKCS11.Token token = (CAPI.PKCS11.Token)store; 

			            // создать диалог свойств
			            ReaderDialog dialog = new ReaderDialog(token); 

			            // показать диалог импорта
			            dialog.ShowDialog(mainForm); 
                    }
                }
            }
            catch {}
        }
		// удалить объект
		public override void DeleteObject(ConsoleNode node) 
		{ 
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

            // указать способ выбора аутентификации 
            AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

            // удалить дочернее хранилище объектов
            selector.DeleteObject(provider, storeInfo.Scope, storeInfo.FullName); 
 		}
		// удалить дочерние объекты
        public override void DeleteChilds(ConsoleNode node, ConsoleNode[] nodes) 
        { 
    		// получить предупреждение об удалении
			string message = Resource.QuestionDeleteObjects; 

			// получить подтверждение об удалении
			if (DialogResult.Yes != MessageBox.Show(node.MainForm, message, 
				node.MainForm.Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question)) return;
            try { 
                // удалить контейнеры
                base.DeleteChilds(node, nodes); 

			    // получить сообщение о завершении
			    message = Resource.StatusDeleteContainers;

			    // вывести ее описание
			    MessageBox.Show(node.MainForm, message, node.MainForm.Text, 
				    MessageBoxButtons.OK, MessageBoxIcon.Information); return;   
            }
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(node.MainForm, ex); return; }
        } 
		private void OnGenerateKeyPair(ConsoleNode node, object sender, EventArgs e)
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

			// создать диалог генерации 
			KeyGenDialog dialogCreate = new KeyGenDialog(
                environment, provider, storeType, storeInfo, null
            ); 
			// показать диалог генерации
			if (dialogCreate.ShowDialog(mainForm) == DialogResult.OK) node.Refresh(); 
		}
		private void OnImportKeyPair(ConsoleNode node, object sender, EventArgs e)
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

			// создать диалог импорта
			KeyImpDialog dialogImport = new KeyImpDialog(
                environment, provider, storeType, storeInfo, null
            ); 
			// показать диалог импорта
			if (dialogImport.ShowDialog(mainForm) == DialogResult.OK) node.Refresh(); 
		}
		private void OnChangeLogin(ConsoleNode node, object sender, EventArgs e)
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm;

            // указать способ выбора аутентификации 
            AuthenticationSelector selector = AuthenticationSelector.Create(mainForm);
            try { 
                // открыть хранилище объектов
                using (SecurityStore store = (SecurityStore)selector.OpenObject(
                    provider, storeInfo.Scope, storeInfo.FullName, FileAccess.ReadWrite))
                { 
                    // выполнить аутентификацию и изменить аутентификационные данные
                    store.Authenticate(); AuthenticationDialog.ShowChange(mainForm, store, selector.User); 

			        // получить подтверждение об удалении
			        MessageBox.Show(mainForm, Resource.MessageChangeLogin, 
				        mainForm.Text, MessageBoxButtons.OK, MessageBoxIcon.Information
                    ); 
                }
            }
			// обработать отмену операции
			catch (OperationCanceledException) {}

			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); }
		}
		private void OnManageDirectories(ConsoleNode node, object sender, EventArgs e)
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

            // указать способ выбора аутентификации 
            AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

            // открыть хранилище объектов
            using (SecurityObject store = selector.OpenObject(
                provider, storeInfo.Scope, storeInfo.FullName, FileAccess.ReadWrite))
            {
			    // создать диалог управления каталогами
			    DirectoriesDialog dialogDirectories = new DirectoriesDialog(
                    mainForm, (Software.DirectoriesStore)store
                ); 
			    // показать диалог управления каталогами
			    if (dialogDirectories.ShowDialog(mainForm) == DialogResult.OK) node.Refresh();
            }
		}
	}
}
