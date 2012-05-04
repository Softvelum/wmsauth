using System;
using Microsoft.WindowsMediaServices.Interop;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using AuthorizedURLProcessor;
using log4net;
using log4net.Config;

namespace CURLPackage
{

	[Guid("01BE10EE-5817-44d9-946A-C41EEAB04043")]
	public class URLAuthorizationPlugin: IWMSBasicPlugin, IWMSEventAuthorizationPlugin	
	{
		private URLProcessor url_procesor = null;
        private static readonly ILog log = LogManager.GetLogger("authorizationpluginlog");
		public URLAuthorizationPlugin()
		{
            string system32dir = System.IO.Directory.GetCurrentDirectory();
            string logfilename = system32dir + "\\windows media\\server\\logconfig.xml";
            XmlConfigurator.ConfigureAndWatch(new System.IO.FileInfo(logfilename));     
            log.Info("plugin object created");

            url_procesor = new URLProcessor();
		}
		#region IWMSBasicPlugin Members

		public void OnHeartbeat()
		{
		}

		public void DisablePlugin()
		{
            log.Info("disable plugin event");
		}

		public object GetCustomAdminInterface()
		{
			return null;
		}

		public void EnablePlugin(ref int plFlags, ref int plHeartbeatPeriod)
		{
            log.Info("enabled plugin event");
		}

		public void ShutdownPlugin()
		{
            log.Info("plugin shutdown event");
		}

		public void InitializePlugin(IWMSContext pServerContext, WMSNamedValues pNamedValues, IWMSClassObject pClassFactory)
		{
            log.Info("plugin initialize event");
		}

		#endregion

		#region IWMSEventAuthorizationPlugin members 

		public void AuthorizeEvent(ref WMS_EVENT pEvent, IWMSContext pUserCtx, IWMSContext pPresentationCtx, IWMSCommandContext pCommandCtx,
							IWMSEventAuthorizationCallback pCallback,
							object Context)
		{
			int hr = 0; // By deafault access is granted to user
			const int ACCESS_DENIED = unchecked((int)0x80070005);
			
			string initial_request = null;
			string user_ip_address = null;
            string user_agent = null;

			pPresentationCtx.GetStringValue(WMSDefines.WMS_PRESENT_REQUEST_NAME,
											WMSDefines.WMS_PRESENT_REQUEST_NAME_ID,
											out initial_request,
											0);
			pUserCtx.GetStringValue(WMSDefines.WMS_USER_IP_ADDRESS_STRING,
									WMSDefines.WMS_USER_IP_ADDRESS_STRING_ID,
									out user_ip_address,
				                    0);
            if (log.IsInfoEnabled)
            {
                pUserCtx.GetStringValue(WMSDefines.WMS_USER_AGENT,
                                        WMSDefines.WMS_USER_AGENT_ID,
                                        out user_agent,
				                        0);
                
            }

            URLValidationExceptionTyte errortype = url_procesor.CheckURLValidity(initial_request,
                                                                                 user_ip_address);
            if (URLValidationExceptionTyte.SUCCESS != errortype)
			{
				hr = ACCESS_DENIED;
			}
            
            if (log.IsInfoEnabled)
            {
                StringBuilder msg = new StringBuilder();
                if(user_agent != null)msg.Append("User-Agent="+ user_agent);
                msg.Append(" User-Ip-Address="+user_ip_address);
                msg.Append(" Request="+initial_request);
                msg.Append(" Autorization-Result=" + errortype.ToString());
                log.Info(msg.ToString());
            }

			pCallback.OnAuthorizeEvent(hr, Context);
			
		}

		public object GetAuthorizedEvents()
		{
				// Identify the events the plug-in can authorize.
				WMS_EVENT_TYPE[] wmsEvents = {WMS_EVENT_TYPE.WMS_EVENT_OPEN};
				return (object)wmsEvents;
		}
		
		#endregion

		[ComRegisterFunctionAttribute]
		public static void RegisterFunction(Type t)
		{
			try
			{
				RegistryKey regHKLM = Registry.LocalMachine;
				regHKLM = regHKLM.CreateSubKey("SOFTWARE\\Microsoft\\Windows Media\\Server\\RegisteredPlugins\\Event Notification and Authorization\\{01BE10EE-5817-44d9-946A-C41EEAB04043}");
				regHKLM.SetValue(null, "Authorization URL based plugin"); 

				RegistryKey regHKCR = Registry.ClassesRoot;
				regHKCR = regHKCR.CreateSubKey("CLSID\\{01BE10EE-5817-44d9-946A-C41EEAB04043}\\Properties");
				regHKCR.SetValue("Name", "Authorization URL based plugin");
				regHKCR.SetValue("Author", "Polox Group");
				regHKCR.SetValue("Copyright", "Copyright 2007. All rights reserved");
				regHKCR.SetValue("Description", "Enable to protect video contents based on URL authorization");
				regHKCR.SetValue("SubCategory", "Authorize");
			}
			catch(Exception e)
			{
				// too strange 
			}
		}
		[ComUnregisterFunctionAttribute]
		public static void UnRegisterFunction(Type t)
		{
			try
			{
				RegistryKey regHKLM = Registry.LocalMachine;
				regHKLM.DeleteSubKey("SOFTWARE\\Microsoft\\Windows Media\\Server\\RegisteredPlugins\\Event Notification and Authorization\\{01BE10EE-5817-44d9-946A-C41EEAB04043}");

				RegistryKey regHKCR = Registry.ClassesRoot;
				regHKCR.DeleteSubKeyTree("CLSID\\{01BE10EE-5817-44d9-946A-C41EEAB04043}");
				regHKCR.DeleteSubKeyTree("CURLPackage.URLAuthorizationPlugin");
			}
			catch(Exception e)
			{
			}
		}

	}
}