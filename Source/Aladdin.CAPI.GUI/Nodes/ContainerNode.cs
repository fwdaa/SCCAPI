using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Контейнер
	///////////////////////////////////////////////////////////////////////////
	internal class ContainerNode : ConsoleForm.Node
	{
		private CryptoEnvironment environment;	  // криптографическая среда
        private CryptoProvider	  provider;       // криптографический провайдер
        private Type			  storeType;      // тип хранилища объекта
		private SecurityInfo	  storeInfo;      // информация хранилища
		private SecurityInfo	  containerInfo;  // информация контейнера
		
		// конструктор
		public ContainerNode(CryptoEnvironment environment, CryptoProvider provider, 
            Type storeType, SecurityInfo storeInfo, SecurityInfo containerInfo) 
		{ 
			// сохранить переданные данные
			this.environment = environment; this.provider = provider; 
            
			// сохранить переданные данные
            this.storeType = storeType; this.storeInfo = storeInfo; 
			
			// сохранить переданные данные
			this.containerInfo = containerInfo; 
		} 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Container.ico"; }
		// значение узла
		public override string Label { get { return containerInfo.Name.ToString(); }}

		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 
		// признак допустимости удаления 
		public override bool CanDelete { get { return true; }}

		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}
		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 
             
			// указать способ аутентификации
			AuthenticationSelector selector = AuthenticationSelector.Create(
				mainForm, environment.AuthenticationAttempts
			); 
			// получить интерфейс клиента
			using (ClientContainer container = new ClientContainer(provider, containerInfo, selector))
            try { 
				// перечислить пары ключей контейнера
				ContainerKeyPair[] keyPairs = container.EnumerateKeyPairs(); 

				// создать список дочерних узлов
				ConsoleForm.Node[] nodes = new ConsoleForm.Node[keyPairs.Length]; 

				// заполнить список дочерних узлов
				for (int i = 0; i < keyPairs.Length; i++)
				{
					// создать узел сертификата
					nodes[i] = new KeyPairNode(environment, provider, keyPairs[i]); 
				}
				return nodes; 
            }
            // обработать возможное исключение
            catch { return new ConsoleForm.Node[0]; } 
		}
		// удалить объект
		public override void DeleteObject(ConsoleNode node) 
		{ 
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

			// указать способ аутентификации
			AuthenticationSelector selector = AuthenticationSelector.Create(
				mainForm, environment.AuthenticationAttempts
			); 
			// удалить используемый контейнер
			selector.DeleteObject(provider, containerInfo.Scope, containerInfo.FullName); 
		}
		// удалить объекты
        public override void DeleteChilds(ConsoleNode node, ConsoleNode[] nodes)
        {
			// получить сообщение
			string message = Resource.QuestionDeleteObjects; 

			// получить подтверждение об удалении
			if (DialogResult.Yes != MessageBox.Show(node.MainForm, message, 
				node.MainForm.Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question)) return; 
			try { 
				// удалить контейнеры
				base.DeleteChilds(node, nodes); 

				// получить сообщение о завершении
				message = Resource.StatusDeleteKeyPairs;

				// вывести ее описание
				MessageBox.Show(node.MainForm, message, node.MainForm.Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information); 
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(node.MainForm, ex); }
        }
		// элементы контекстного меню для узла
		public override ToolStripItem[] GetContextMenuItems(ConsoleNode node) 
		{ 
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

            // создать список элементов меню
			List<ToolStripItem> items = new List<ToolStripItem>(); bool canChangeLongin = false;

            // указать способ выбора аутентификации
            AuthenticationSelector selector = AuthenticationSelector.Create(
				mainForm, environment.AuthenticationAttempts);
            try { 
				// открыть контейнер
				using (Container obj = (Container)selector.OpenObject(
					provider, containerInfo.Scope, containerInfo.FullName, FileAccess.Read))
				{
					// для всех поддерживаемых типов аутентификации
					foreach (Type authenticationType in obj.GetAuthenticationTypes(selector.User))
					try {
						// получить сервис аутентификации
						AuthenticationService service = obj.GetAuthenticationService(
							selector.User, authenticationType
						); 
						// добавить тип используемой аутентификации
						if (service.CanChange) { canChangeLongin = true; break; }
					}
					catch {}
				}
            }
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); return items.ToArray(); }

			// добавить элементы контекстного меню
            items.Add(new ToolStripMenuItem(Resource.MenuGenerateKeyPair, null, 
				delegate (object sender, EventArgs e) { OnGenerateKeyPair(node, sender, e); }
			));
            items.Add(new ToolStripMenuItem(Resource.MenuImportKeyPair, null, 
				delegate (object sender, EventArgs e) { OnImportKeyPair(node, sender, e); }
			));
            if (canChangeLongin) 
            { 
                items.Add(new ToolStripSeparator());
                items.Add(new ToolStripMenuItem(Resource.MenuChangeLogin, null, 
				    delegate (object sender, EventArgs e) { OnChangeLogin(node, sender, e); }
			    ));
                items.Add(new ToolStripSeparator());
            }
            items.Add(new ToolStripMenuItem(Resource.MenuViewCertificates, null, 
				delegate (object sender, EventArgs e) { OnViewCertificates(node, sender, e); }
			));
            return items.ToArray(); 
		}
		private void OnViewCertificates(ConsoleNode node, object sender, EventArgs e)
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm;
            try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					mainForm, environment.AuthenticationAttempts
				); 
				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, containerInfo, selector))
				{ 
					// перечислить все сертификаты контейнера
					Certificate[] certificates = container.EnumerateAllCertificates(); 

					// показать сертификаты
					CertificatesDialog.Show(mainForm, certificates); 
				}
            }
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); }
        }
		private void OnGenerateKeyPair(ConsoleNode node, object sender, EventArgs e)
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

			// создать диалог генерации 
			KeyGenDialog dialogCreate = new KeyGenDialog( 
                environment, provider, storeType, 
				storeInfo, containerInfo.Name.ToString()
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
				environment, provider, storeType, 
				storeInfo, containerInfo.Name.ToString()
			); 
			// показать диалог импорта
			if (dialogImport.ShowDialog(mainForm) == DialogResult.OK) node.Refresh(); 
		}
		private void OnChangeLogin(ConsoleNode node, object sender, EventArgs e)
		{
			// определить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm;

            // указать способ выбора аутентификации
            AuthenticationSelector selector = AuthenticationSelector.Create(
				mainForm, environment.AuthenticationAttempts);
            try { 
				// открыть контейнер
				using (Container obj = (Container)selector.OpenObject(
					provider, containerInfo.Scope, containerInfo.FullName, FileAccess.ReadWrite))
				{ 
					// выполнить аутентификацию и изменить аутентификационные данные
					obj.Authenticate(); AuthenticationDialog.ShowChange(
						mainForm, obj, selector.User, environment.AuthenticationAttempts
					); 
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
	}
}
