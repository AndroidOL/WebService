using System;
using System.Data;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;
using System.IO;
using System.Data.SqlClient;
using System.Xml;
using System.Text;
using System.Globalization;
using System.Collections.Generic;

namespace WebServicePark
{
    public static class CPublic
    {
        public static string LocalNode = "";
        public static string AppPath = "";
        public static string LogPath = @"D:\WebServices\";
        public static string ConnString = "";//@"Data Source=127.0.0.1;Initial Catalog=ConCard;User ID=sa;Password=2008sa";
        public static List<string> myFunc = new List<string>();
        //public static SqlConnection conn = new SqlConnection();

        //@"Data Source=" + IP + ";Initial Catalog=SMS;User ID=" + UserName + ";Password=" + Password;
        public static int Init()
        {
            try
            {
                if (!Directory.Exists(CPublic.LogPath))
                    Directory.CreateDirectory(CPublic.LogPath);

                //conn.ConnectionString = ConnString;
                //conn.Open();
                if (File.Exists(AppPath + "DBConfig.cfg"))
                {
                    using (FileStream fs = new FileStream(AppPath + "DBConfig.cfg", FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        byte[] buf = new byte[2048];
                        int nReadNum = fs.Read(buf, 0, 2048);
                        if (nReadNum != 2048)
                        {
                            CPublic.WriteLog("读取数据库连年配置文件失败,长度不足.");
                        }
                        else
                        {
                            EncryptHelper eh = new EncryptHelper();

                            int len = BitConverter.ToInt32(buf, 0);
                            ConnString = eh.DesDecrypt(Encoding.GetEncoding("gb2312").GetString(buf, 4, len), "synjones");

                            len = BitConverter.ToInt32(buf, 1024);
                            string ConOperKey = eh.DesDecrypt(Encoding.GetEncoding("gb2312").GetString(buf, 1028, len), "synjones");
                        }
                    }
                }
                else
                {
                    CPublic.WriteLog("数据库连接配置文件不存在,请使用工具生,并放在目录:" + AppPath);
                }

                return 0;
            }
            catch (Exception e)
            {
                CPublic.WriteLog("初始化异常:" + e.Message);
                return -1;
            }
        }
        public static bool AuthUpdate() {
            try {
                myFunc.Clear();
                ExeConfigurationFileMap map = new ExeConfigurationFileMap();
                map.ExeConfigFilename = CPublic.AppPath + "setting.xml";
                Configuration config = ConfigurationManager.OpenMappedExeConfiguration(map, ConfigurationUserLevel.None);
                if (config.Sections["appSettings"] != null) {
                    KeyValueConfigurationCollection kv = config.AppSettings.Settings;

                    foreach(KeyValueConfigurationElement el in kv) {
                        if (el.Value == "0") {
                            myFunc.Add(el.Key);
                        }
                    }
                    return true;
                }
            } catch { return false; }
            return false;
        }
        public static int WriteLog(string Msg)
        {
            try
            {
                string CurLog = LogPath + DateTime.Today.ToShortDateString() + ".txt";
                FileStream fs = new FileStream(CurLog, FileMode.Append, FileAccess.Write, FileShare.None);
                StreamWriter sw = new StreamWriter(fs);
                sw.WriteLine(DateTime.Now.ToLongTimeString() + " ： " + Msg);
                sw.Close();
            }
            catch
            {
                return -1;
            }

            return 0;
        }

        /// <summary>
        /// 把从第三方接口中提取的日期,转成标准的日期格式
        /// </summary>
        /// <param name="birthday"></param>
        /// <returns></returns>
        public static string ConvertDateTime(byte[] birthday)
        {
            string YY = string.Empty;
            string MM = string.Empty;
            string DD = string.Empty;
            string hh = string.Empty;
            string mm = string.Empty;
            string ss = string.Empty;
            string dt = string.Empty;

            if (birthday[0] == '\0')
            {
                dt = string.Empty;
                YY = "1900";
                MM = "00";
                DD = "00";
                hh = "00";
                mm = "00";
                ss = "00";
            }
            else
            {
                dt = System.Text.Encoding.Default.GetString(birthday);
                YY = dt.Substring(0, 4);
                MM = dt.Substring(4, 2);
                DD = dt.Substring(6, 2);
                hh = dt.Substring(8, 2);
                mm = dt.Substring(10, 2);
                ss = dt.Substring(12, 2);

            }
            dt = YY + "-" + MM + "-" + DD + " " + hh + ":" + mm + ":" + ss;
            return dt;
        }
        public static string ByteArrayToStr(byte[] ByteArray)
        {
            if (ByteArray == null)
                return "";

            int len = 0;
            foreach (byte b in ByteArray)
            {
                if (b == 0)
                    break;

                len++;
            }

            return Encoding.GetEncoding("gb2312").GetString(ByteArray, 0, len);
        }
        public static string ByteArrayToStr(byte[] ByteArray, int offset, int length)
        {
            if (ByteArray == null)
                return "";

            if (length > ByteArray.Length - offset)
                return "";

            byte[] buf = new byte[length];
            Array.Copy(ByteArray, offset, buf, 0, length);

            int len = 0;
            foreach (byte b in buf)
            {
                if (b == 0)
                    break;

                len++;
            }

            return Encoding.GetEncoding("gb2312").GetString(buf, 0, len);
        }
    }
}

