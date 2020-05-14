using System;
using System.Collections;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.SessionState;
using System.Xml.Linq;
using System.IO;
using System.Threading;

namespace WebServicePark
{
    public class Global : System.Web.HttpApplication
    {

        protected void Application_Start(object sender, EventArgs e)
        {
            CPublic.AppPath = Server.MapPath(@"\");
            CPublic.LogPath = CPublic.AppPath + "Log\\";
            CPublic.AuthUpdate();
            //int nRet = CPublic.Init();
            //if (nRet != 0)
            //{
            //    CPublic.WriteLog("Web Service 初始化失败,nRet=" + nRet.ToString());
            //}
            int nRet = TPE_Class.TPE_GetNetState();
            if (nRet != 3)
            {
                TPE_Class.TPE_StartTPE();
            }
            for (int i = 0; i < 20; i++)
            {
                nRet = TPE_Class.TPE_GetNetState();
                if (nRet == 3)
                {
                    nRet = TPE_Class.TPE_GetLocalNode();                    
                    CPublic.LocalNode = nRet.ToString();
                    CPublic.WriteLog("TPE LocalNode " + nRet);
                    CPublic.WriteLog("TPE OK " + i);
                    break;
                }
                Thread.Sleep(1000);
            }
            CPublic.WriteLog("Application_Start");
        }

        protected void Session_Start(object sender, EventArgs e)
        {
            CPublic.WriteLog("Session_Start");
        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            CPublic.WriteLog("Application_BeginRequest");
        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {
            CPublic.WriteLog("Application_AuthenticateRequest");
        }

        protected void Application_Error(object sender, EventArgs e)
        {
            CPublic.WriteLog("Application_Error");
        }

        protected void Session_End(object sender, EventArgs e)
        {
            TPE_Class.TPE_StopTPE();

            CPublic.WriteLog("Session_End");
        }

        protected void Application_End(object sender, EventArgs e)
        {
            TPE_Class.TPE_StopTPE();
            CPublic.WriteLog("Application_End");
        }
    }
}