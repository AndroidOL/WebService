using System;
using System.Collections.Generic;
using System.Web.Services;
using System.Web.Script.Serialization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.Remoting.Messaging;

namespace WebServicePark {

    struct ConditionInfo
    {
        public bool isUsable;
        public bool isWithdrawal;
        public bool isFreezing;
        public bool isLost;
        public bool isTransfer;
        public bool isGender;
        public bool isMale;
        public bool isUpdate;

    };



    /// <summary>
    /// IParkService 的摘要说明
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // 若要允许使用 ASP.NET AJAX 从脚本中调用此 Web 服务，请取消对下行的注释。
    [System.Web.Script.Services.ScriptService]
    public class IParkService : System.Web.Services.WebService
    {
        public static bool IsNumeric(string value)
        {
            return Regex.IsMatch(value, @"^[+-]?\d*[.]?\d*$");
        }
        public static bool IsInt(string value)
        {
            return Regex.IsMatch(value, @"^[+-]?\d*$");
        }

        public static bool GetBit(UInt32 Condi, int Bit)
        {
            if (Bit >= 0 && Bit <= 31)
            {
                UInt32 tmp = 1;
                UInt32 ret = Condi & (tmp << Bit);
                return ret > 0 ? true : false;
            }
            return false;
        }


        string[] NodeCheckInfo = new string[] {
            "节点验证成功，数据校验正确",
            "节点验证失败，请检查证书、第三方加密狗以及平台是否正常，重启中心平台或尝试将证书文件放置于 SysWow64 文件夹下",
            "节点验证成功，数据校验失败",
            "查询节点失败，请检查是否已添加节点"

        };
        /// <summary>
        /// 调帐
        /// </summary>
        /// <param name="Condition">Condition</param>
        /// <returns>json </returns>
        [WebMethod]
        public string TPE_ConditionParse(string Condition)
        {
            CReturnFlowRes retRes = new CReturnFlowRes();
            string json = "";

            ConditionInfo CI;
            CI.isUsable = false;
            CI.isWithdrawal = false;
            CI.isFreezing = false;
            CI.isLost = false;
            CI.isTransfer = false;
            CI.isMale = false;
            CI.isGender = false;
            CI.isUpdate = false;

            try {
                if (!IsInt(Condition)){
                    throw new ArgumentException("Condition 必须是一个整数"); 
                }
                UInt32 condt = UInt32.Parse(Condition);
                CI.isUsable = GetBit(condt, 0);
                CI.isWithdrawal = GetBit(condt, 1);
                CI.isFreezing = GetBit(condt, 2);
                CI.isLost = GetBit(condt, 3);
                CI.isTransfer = GetBit(condt, 4);
                CI.isGender = GetBit(condt, 16);
                CI.isMale = !GetBit(condt, 17);
                CI.isUpdate = true;

                retRes.Result = "OK";
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(CI);
                retRes.Msg = json;
                CI.isUpdate = false;
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("解析：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("解析 ToJson:" + ex.Message);
            }
            return json;
        }
        /// <summary>
        /// 调帐
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC(加密过程请查看CheckNode()方法)</param>
        /// <param name="CardNo">卡号</param>
        /// <returns>json </returns>
        [WebMethod]
        public string TPE_LostAccount(string NodeNo, string AccountNo, string PassWord, string Operation, string MAC)
        {
            CReturnFlowRes retRes = new CReturnFlowRes();
            string json = "";
            try
            {
                int nodeNo; int accNo; byte operation;
                string param = AccountNo + "$" + PassWord + "$" + Operation;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(AccountNo) || !int.TryParse(AccountNo, out accNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(PassWord))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[PassWord]";
                }
                else if (string.IsNullOrEmpty(Operation) || !byte.TryParse(Operation, out operation))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[Operation(类型Int)]";
                }
                else if (CheckNode(NodeNo, param, MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                }
                else
                {
                    if (System.Convert.ToInt32(Operation) == 1) {
                        operation = 1;
                    } else { operation = 2; }
                    if (operation == 1)
                    {

                        //验密
                        tagTPE_GetAccountReq Req = new tagTPE_GetAccountReq();
                        tagTPE_GetAccountRes Res = new tagTPE_GetAccountRes();
                        Req.AccountNo = System.Convert.ToUInt32(AccountNo);
                        int nRet = TPE_Class.TPE_GetAccount(1, ref Req, out Res, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "调账失败 nRet=" + nRet.ToString();
                        }
                        else
                        {
                            tagTPE_OnLineGetMaxSnRes SnRes = new tagTPE_OnLineGetMaxSnRes();
                            TPE_Class.TPE_OnLineGetMaxSn(1, out SnRes, 1);
                            tagTPE_LostReq ReqL = new tagTPE_LostReq();
                            tagTPE_FlowRes ResF = new tagTPE_FlowRes();
                            ReqL.OccurIdNo = SnRes.MaxSn + 1;
                            ReqL.OccurTime = DateTime.Now.ToString("yyyyMMddHHmmss");
                            ReqL.Operation = 1;
                            ReqL.ReqAccountNo = System.Convert.ToInt32(AccountNo);

                            nRet = TPE_Class.TPE_Lost(1, ref ReqL, out ResF, 1);
                            if (nRet != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "nRet=" + nRet.ToString();
                            }
                            else
                            {
                                TPE_FlowRes Fr = new TPE_FlowRes(ResF);
                                Fr.CenterNo = QueryOccurByCenter(NodeNo, Fr.OccurIdNo);
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.Data = Fr;
                            }
                        }

                    } else
                    {
                        //验密
                        tagTPE_GetAccountReq Req = new tagTPE_GetAccountReq();
                        tagTPE_GetAccountRes Res = new tagTPE_GetAccountRes();
                        Req.reqflagPassword = '1';
                        Req.AccountNo = System.Convert.ToUInt32(AccountNo);
                        Req.Password = new byte[8];
                        var tmp = System.Text.Encoding.ASCII.GetBytes(PassWord);
                        Array.Copy(tmp, Req.Password, tmp.Length > 8 ? 8 : tmp.Length);
                        int nRet = TPE_Class.TPE_GetAccount(1, ref Req, out Res, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "验密 nRet=" + nRet.ToString();
                        }
                        else
                        {
                            if (Res.RetValue != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "验密 RetValue=" + Res.RetValue.ToString();
                            }
                            else
                            {
                                tagTPE_OnLineGetMaxSnRes SnRes = new tagTPE_OnLineGetMaxSnRes();
                                TPE_Class.TPE_OnLineGetMaxSn(1, out SnRes, 1);
                                tagTPE_LostReq ReqL = new tagTPE_LostReq();
                                tagTPE_FlowRes ResF = new tagTPE_FlowRes();
                                ReqL.OccurIdNo = SnRes.MaxSn + 1;
                                ReqL.OccurTime = DateTime.Now.ToString("yyyyMMddHHmmss");
                                ReqL.Operation = operation;
                                ReqL.ReqAccountNo = System.Convert.ToInt32(AccountNo);

                                nRet = TPE_Class.TPE_Lost(1, ref ReqL, out ResF, 1);
                                if (nRet != 0)
                                {
                                    retRes.Result = "error";
                                    retRes.Msg = "nRet=" + nRet.ToString();
                                }
                                else
                                {
                                    TPE_FlowRes Fr = new TPE_FlowRes(ResF);
                                    Fr.CenterNo = QueryOccurByCenter(NodeNo, Fr.OccurIdNo);
                                    retRes.Result = "ok";
                                    retRes.Msg = "成功";
                                    retRes.Data = Fr;
                                }
                            }
                        }

                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("挂失异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("挂失 ToJson:" + ex.Message);
            }
            return json;
        }
        /// <summary>
        /// 修改密码
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="AccountNo">帐号(卡号传入一项即可)</param>
        /// <param name="CardNo">卡号(帐号传入一项即可)</param>
        /// <param name="OldPassWord">原密码</param>
        /// <param name="NewPassWord">新密码</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        public string TPE_ChangeAccountPassword(string NodeNo, string AccountNo, string CardNo, string OldPassWord, string NewPassWord, string MAC)
        {
            CReturnFlowUpdateAccountRes retRes = new CReturnFlowUpdateAccountRes();
            string json = "";
            try
            {
                int nodeNo; int accNo; int cardNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(AccountNo) && string.IsNullOrEmpty(CardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo/CardNo(至少传入一项)]";
                }
                else if (!string.IsNullOrEmpty(AccountNo) && !int.TryParse(AccountNo, out accNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo(类型Int)]";
                }
                else if (!string.IsNullOrEmpty(CardNo) && !int.TryParse(CardNo, out cardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[CardNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(OldPassWord))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[OldPassWord]";
                }
                else if (string.IsNullOrEmpty(NewPassWord))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NewPassWord]";
                }
                else
                {
                    string param = "";
                    if (!string.IsNullOrEmpty(AccountNo))
                    {
                        param = AccountNo;
                    }
                    else if (string.IsNullOrEmpty(AccountNo) && !string.IsNullOrEmpty(CardNo))
                    {
                        param = CardNo;
                    }
                    else if (!string.IsNullOrEmpty(AccountNo) && !string.IsNullOrEmpty(CardNo))
                    {
                        param = AccountNo + "$" + CardNo;
                    }
                    if (CheckNode(NodeNo, param + "$" + OldPassWord + "$" + NewPassWord, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param + "$" + OldPassWord + "$" + NewPassWord, MAC)];
                    }
                    else
                    {
                        //验密
                        tagTPE_GetAccountReq Req = new tagTPE_GetAccountReq();
                        tagTPE_GetAccountRes Res = new tagTPE_GetAccountRes();
                        Req.reqflagPassword = '1';
                        if (!string.IsNullOrEmpty(AccountNo))
                        {
                            Req.AccountNo = System.Convert.ToUInt32(AccountNo);
                        }
                        if (!string.IsNullOrEmpty(CardNo))
                        {
                            Req.CardNo = System.Convert.ToInt32(CardNo);
                        }
                        Req.Password = new byte[8];
                        byte[] tmp = System.Text.Encoding.ASCII.GetBytes(OldPassWord);
                        Array.Copy(tmp, Req.Password, tmp.Length > 8 ? 8 : tmp.Length);
                        int nRet = TPE_Class.TPE_GetAccount(1, ref Req, out Res, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "验密 nRet=" + nRet.ToString();
                        }
                        else
                        {
                            if (Res.RetValue != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "验密 RetValue=" + Res.RetValue.ToString();
                            }
                            else
                            {
                                tagTPE_OnLineGetMaxSnRes SnRes = new tagTPE_OnLineGetMaxSnRes();
                                TPE_Class.TPE_OnLineGetMaxSn(1, out SnRes, 1);
                                tagTPE_FlowUpdateAccountReq ReqU = new tagTPE_FlowUpdateAccountReq();
                                tagTPE_FlowUpdateAccountRes ResU = new tagTPE_FlowUpdateAccountRes();
                                ReqU.TranOper = 0;
                                ReqU.reqflagPassword = 1;
                                ReqU.OccurIdNo = (UInt32)(SnRes.MaxSn + 1);
                                ReqU.OccurTime = new byte[14];
                                tmp = System.Text.Encoding.ASCII.GetBytes(DateTime.Now.ToString("yyyyMMddHHmmss"));
                                Array.Copy(tmp, ReqU.OccurTime, tmp.Length);
                                if (!string.IsNullOrEmpty(AccountNo))
                                {
                                    ReqU.ReqAccountNo = System.Convert.ToUInt32(AccountNo);
                                }
                                if (!string.IsNullOrEmpty(CardNo))
                                {
                                    ReqU.ReqCardNo = System.Convert.ToInt32(CardNo);
                                }
                                ReqU.Password = new byte[8];
                                tmp = System.Text.Encoding.ASCII.GetBytes(NewPassWord);
                                Array.Copy(tmp, ReqU.Password, tmp.Length > 8 ? 8 : tmp.Length);

                                nRet = TPE_Class.TPE_FlowUpdateAccount(1, ref ReqU, out ResU, 1);
                                if (nRet != 0)
                                {
                                    retRes.Result = "error";
                                    retRes.Msg = "nRet=" + nRet.ToString();
                                }
                                else
                                {
                                    if (ResU.RecordError != 0)
                                    {
                                        retRes.Result = "error";
                                        retRes.Msg = "RecordError=" + ResU.RecordError.ToString();
                                    }
                                    else
                                    {
                                        TPE_FlowUpdateAccountRes Fuar = new TPE_FlowUpdateAccountRes(ResU);
                                        Fuar.CenterNo = QueryOccurByCenterUINT(NodeNo, Fuar.OccurIdNo);
                                        retRes.Result = "ok";
                                        retRes.Msg = "成功";
                                        retRes.Data = Fuar;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("修改密码 异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("修改密码 异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 调帐
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC(加密过程请查看CheckNode()方法)</param>
        /// <param name="CardNo">卡号</param>
        /// <returns>json </returns>
        [WebMethod]
        public string TPE_GetAccount(string NodeNo, string CardNo, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            string json = "";
            try
            {
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(CardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[CardNo]";
                }
                else
                {
                    string param = "";
                    if (!string.IsNullOrEmpty(CardNo))
                    {
                        param = CardNo;
                    }

                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                    }
                    else
                    {
                        tagTPE_GetAccountReq Req = new tagTPE_GetAccountReq();
                        tagTPE_GetAccountRes Res = new tagTPE_GetAccountRes();
                        if (!string.IsNullOrEmpty(CardNo))
                        {
                            Req.CardNo = System.Convert.ToInt32(CardNo);
                        }
                        /*经常会有这样的检索条件,AccountNo , CardNo , JoinNode,JoinCardHolder
                          TPE在处理时优先级按帐号>卡号>对应关系来处理,过渡的条件为前面字段=0;
                          调帐交易中用户可以定义自己需要的字段,如果不需要的字段可以不选择,网络上也不会传输
                          ,这样会提高传输速度,因此使用者应该根据自己的需要来调所需要的字段,不要盲目的全部调.
                          此外<帐号,卡号,状态,余额,开户日期,密码,访问控制>在数据中心的高速缓冲内,不需要访
                          问数据库,速度为其它字段的1000倍以上,因此,一般情况下,应该优先考虑使用这些字段.*/
                        Req.resflagAccountNo = 1;     //帐号
                        Req.resflagCardNo = 1;        //卡号
                        Req.resflagCondition = 1;     //状态
                        Req.resflagBalance = 1;       //余额
                        Req.resflagCreateTime = 1;    //开户时间 
                        Req.resflagExpireDate = 1;    //有效期
                        Req.resflagName = 1;          //姓名
                        Req.resflagPersonID = 1;      //身份证号
                        Req.resflagPassword = 0;      //密码 
                        Req.resflagAccessControl = 1; //访问控制,
                        Req.resflagBirthday = 1;      //出生日期
                        Req.resflagDepart = 1;        //部门
                        Req.resflagIdenti = 1;        //身份
                        Req.resflagNation = 1;        //民族国籍
                        Req.resflagCertType = 1;      //证件类型
                        Req.resflagCertCode = 1;      //证件号码
                        Req.resflagCreditCardNo = 0;  //银行卡号
                        Req.resflagTransferLimit = 0; //转帐限额 
                        Req.resflagTransferMoney = 0; //转帐金额
                        Req.resflagTel = 1;           //电话
                        Req.resflagEmail = 1;         //电邮
                        Req.resflagPostalCode = 0;    //邮政编码
                        Req.resflagPostalAddr = 0;    //通信地址
                        Req.resflagFile = 0;          //文件;
                        Req.resflagComment = 0;       //注释
                        Req.resflagExtend = 0;        //扩展
                        Req.resflagUpdateTime = 0;    //最后更新日期
                        int nRet = TPE_Class.TPE_GetAccount(1, ref Req, out Res, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "nRet=" + nRet.ToString();
                        }
                        else
                        {
                            if (Res.RetValue != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "RetValue=" + Res.RetValue.ToString();
                            }
                            else
                            {
                                TPE_GetAccountRes tpe_GetAccRes = new TPE_GetAccountRes(Res);
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.Data = tpe_GetAccRes;
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("调账异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("调账异常 ToJson:" + ex.Message);
            }
            return json;
        }
        /// <summary>
        /// 调帐
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC(加密过程请查看CheckNode()方法)</param>
        /// <param name="AccountNo">帐号(卡号传入一项即可)</param>
        /// <param name="CardNo">卡号(帐号传入一项即可)</param>
        /// <returns>json </returns>
        [WebMethod]
        public string TPE_GetAccountByNo(string NodeNo, string AccountNo, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            string json = "";
            try
            {
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(AccountNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo]";
                }
                else
                {
                    string param = "";
                    if (!string.IsNullOrEmpty(AccountNo))
                    {
                        param = AccountNo;
                    }

                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                    }
                    else
                    {
                        tagTPE_GetAccountReq Req = new tagTPE_GetAccountReq();
                        tagTPE_GetAccountRes Res = new tagTPE_GetAccountRes();
                        if (!string.IsNullOrEmpty(AccountNo))
                        {
                            Req.AccountNo = System.Convert.ToUInt32(AccountNo);
                        }
                        /*经常会有这样的检索条件,AccountNo , CardNo , JoinNode,JoinCardHolder
                          TPE在处理时优先级按帐号>卡号>对应关系来处理,过渡的条件为前面字段=0;
                          调帐交易中用户可以定义自己需要的字段,如果不需要的字段可以不选择,网络上也不会传输
                          ,这样会提高传输速度,因此使用者应该根据自己的需要来调所需要的字段,不要盲目的全部调.
                          此外<帐号,卡号,状态,余额,开户日期,密码,访问控制>在数据中心的高速缓冲内,不需要访
                          问数据库,速度为其它字段的1000倍以上,因此,一般情况下,应该优先考虑使用这些字段.*/
                        Req.resflagAccountNo = 1;     //帐号
                        Req.resflagCardNo = 1;        //卡号
                        Req.resflagCondition = 1;     //状态
                        Req.resflagBalance = 1;       //余额
                        Req.resflagCreateTime = 1;    //开户时间 
                        Req.resflagExpireDate = 1;    //有效期
                        Req.resflagName = 1;          //姓名
                        Req.resflagPersonID = 1;      //身份证号
                        Req.resflagPassword = 0;      //密码 
                        Req.resflagAccessControl = 1; //访问控制,
                        Req.resflagBirthday = 1;      //出生日期
                        Req.resflagDepart = 1;        //部门
                        Req.resflagIdenti = 1;        //身份
                        Req.resflagNation = 1;        //民族国籍
                        Req.resflagCertType = 0;      //证件类型
                        Req.resflagCertCode = 1;      //证件号码
                        Req.resflagCreditCardNo = 0;  //银行卡号
                        Req.resflagTransferLimit = 0; //转帐限额 
                        Req.resflagTransferMoney = 0; //转帐金额
                        Req.resflagTel = 1;           //电话
                        Req.resflagEmail = 0;         //电邮
                        Req.resflagPostalCode = 0;    //邮政编码
                        Req.resflagPostalAddr = 0;    //通信地址
                        Req.resflagFile = 0;          //文件;
                        Req.resflagComment = 0;       //注释
                        Req.resflagExtend = 0;        //扩展
                        Req.resflagUpdateTime = 0;    //最后更新日期
                        int nRet = TPE_Class.TPE_GetAccount(1, ref Req, out Res, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "nRet=" + nRet.ToString();
                        }
                        else
                        {
                            if (Res.RetValue != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "RetValue=" + Res.RetValue.ToString();
                            }
                            else
                            {
                                TPE_GetAccountRes tpe_GetAccRes = new TPE_GetAccountRes(Res);
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.Data = tpe_GetAccRes;
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("调账异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("调账异常 ToJson:" + ex.Message);
            }
            return json;
        }



        ////////!!!!!!!!!!!!!!!!!!!!
        /// <summary>
        /// 调帐
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="CertNo">学工号</param>
        /// <param name="MAC">MAC(加密过程请查看CheckNode()方法)</param>
        /// <returns>json </returns>
        [WebMethod]
        public string TPE_GetAccountByIDNo(string NodeNo, string IDNo, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            List<TPE_GetAccountRes> listRes = new List<TPE_GetAccountRes>();
            string json = "";
            try
            {
                CPublic.WriteLog("TPE_GetAccount NodeNo=" + NodeNo + ";LocalNode=" + CPublic.LocalNode);
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(IDNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[CertNo]";
                }
                else
                {
                    string param = "";
                    if (!string.IsNullOrEmpty(IDNo))
                    {
                        param = IDNo;
                    }

                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                    }
                    else
                    {
                        tagTPE_QueryGeneralAccountReq Req = new tagTPE_QueryGeneralAccountReq();
                        tagTPE_QueryResControl ResControl = new tagTPE_QueryResControl();

                        Req.SQL = "where PersonID = '" + IDNo.Trim() + "'";
                        Req.resflagName = 1;
                        Req.resflagCertCode = 1;
                        Req.resflagBalance = 1;
                        Req.resflagCardNo = 1;
                        Req.resflagCondition = 1;

                        int nRet = TPE_Class.TPE_QueryGeneralAccount(1, ref Req, out ResControl, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "调账失败！ nRet=" + nRet.ToString();
                        }
                        else if (ResControl.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "帐户不存在！";
                        }
                        else
                        {
                            if (ResControl.ResRecCount == 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "ResRecCount=" + ResControl.ResRecCount.ToString();
                            }
                            else
                            {
                                tagTPE_GetAccountRes AccRes_X = new tagTPE_GetAccountRes();
                                TPE_GetAccountRes tpe_GetAccRes_X;
                                IntPtr buffer;
                                unsafe
                                {
                                    for (int i = 0; i < ResControl.ResRecCount; i++)
                                    {
                                        buffer = (IntPtr)((Byte*)(ResControl.pRes) + i * System.Runtime.InteropServices.Marshal.SizeOf(AccRes_X));
                                        AccRes_X = (tagTPE_GetAccountRes)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer, typeof(tagTPE_GetAccountRes));
                                        tpe_GetAccRes_X = new TPE_GetAccountRes(AccRes_X);
                                        listRes.Add(tpe_GetAccRes_X);
                                    }
                                    ResControl.pRes = null;
                                }
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.ListDate = listRes;
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("调账异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("调账异常 ToJson:" + ex.Message);
            }
            return json;
        }



        ////////!!!!!!!!!!!!!!!!!!!!
        /// <summary>
        /// 调帐
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="CertNo">学工号</param>
        /// <param name="MAC">MAC(加密过程请查看CheckNode()方法)</param>
        /// <returns>json </returns>
        [WebMethod]
        public string TPE_GetAccountByCertNo(string NodeNo, string CertNo, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            string json = "";
            try
            {
                CPublic.WriteLog("TPE_GetAccount NodeNo=" + NodeNo + ";LocalNode=" + CPublic.LocalNode);
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(CertNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[CertNo]";
                }
                else
                {
                    string param = "";
                    if (!string.IsNullOrEmpty(CertNo))
                    {
                        param = CertNo;
                    }

                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                    }
                    else
                    {
                        tagTPE_QueryGeneralAccountReq Req = new tagTPE_QueryGeneralAccountReq();
                        tagTPE_QueryResControl ResControl = new tagTPE_QueryResControl();

                        Req.SQL = "where CertCode = '" + CertNo.Trim() + "'";
                        /*经常会有这样的检索条件,AccountNo , CardNo , JoinNode,JoinCardHolder
                          TPE在处理时优先级按帐号>卡号>对应关系来处理,过渡的条件为前面字段=0;
                          调帐交易中用户可以定义自己需要的字段,如果不需要的字段可以不选择,网络上也不会传输
                          ,这样会提高传输速度,因此使用者应该根据自己的需要来调所需要的字段,不要盲目的全部调.
                          此外<帐号,卡号,状态,余额,开户日期,密码,访问控制>在数据中心的高速缓冲内,不需要访
                          问数据库,速度为其它字段的1000倍以上,因此,一般情况下,应该优先考虑使用这些字段.*/
                        Req.resflagCardNo = 1;        //卡号
                        Req.resflagCondition = 1;     //状态
                        Req.resflagBalance = 1;       //余额
                        Req.resflagCreateTime = 1;    //开户时间 
                        Req.resflagExpireDate = 1;    //有效期
                        Req.resflagName = 1;          //姓名
                        Req.resflagPersonID = 0;      //身份证号
                        Req.resflagBirthday = 1;      //出生日期
                        Req.resflagDepart = 1;        //部门
                        Req.resflagIdenti = 1;        //身份
                        Req.resflagNation = 1;        //民族国籍
                        Req.resflagCertType = 1;      //证件类型
                        Req.resflagCertCode = 1;      //证件号码
                        Req.resflagCreditCardNo = 0;  //银行卡号
                        Req.resflagTransferLimit = 0; //转帐限额 
                        Req.resflagTransferMoney = 0; //转帐金额
                        Req.resflagTel = 1;           //电话
                        Req.resflagEmail = 1;         //电邮
                        Req.resflagPostalCode = 0;    //邮政编码
                        Req.resflagPostalAddr = 0;    //通信地址
                        Req.resflagFile = 0;          //文件;
                        Req.resflagComment = 0;       //注释
                        Req.resflagExtend = 0;        //扩展
                        Req.resflagUpdateTime = 0;    //最后更新日期

                        int nRet = TPE_Class.TPE_QueryGeneralAccount(1, ref Req, out ResControl, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "调账失败！ nRet=" + nRet.ToString();
                        }
                        else if (ResControl.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "帐户不存在！";
                        }
                        else if (ResControl.ResRecCount > 1)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "此工号对应帐户不唯一！";
                        }
                        else
                        {
                            tagTPE_GetAccountRes AccRes = new tagTPE_GetAccountRes();
                            unsafe
                            {
                                IntPtr buffer1 = (IntPtr)((Byte*)(ResControl.pRes));
                                AccRes = (tagTPE_GetAccountRes)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer1, typeof(tagTPE_GetAccountRes));
                                try
                                {
                                    ResControl.pRes = null;
                                }
                                catch (Exception ex)
                                {
                                    CPublic.WriteLog("异常:" + ex.Message);
                                }
                            }
                            TPE_GetAccountRes tpe_GetAccRes = new TPE_GetAccountRes(AccRes);


                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.Data = tpe_GetAccRes;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("调账异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("调账异常 ToJson:" + ex.Message);
            }
            return json;
        }
        /// <summary>
        /// 按学工号查询流水
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="CertCode">学工号</param>
        /// <param name="FromCentralNo">开始位置</param>
        /// <param name="ToCentralNo">结束位置</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_QueryFlowByCertNo(string NodeNo, string CertCode, string BeginTime, string EndTime, string MAC)
        {
            CPublic.WriteLog("进入TPE_QueryFlowByAcc CertCode = " + CertCode + ";BeginTime = " + BeginTime + ";EndTime = " + EndTime);
            CReturnCReturnObj retRes = new CReturnCReturnObj();
            List<TPE_CReturnObj> listCRO = new List<TPE_CReturnObj>();
            string json = "";
            try
            {
                int nodeNo;
                string param = CertCode + "$" + BeginTime + "$" + EndTime;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (CheckNode(NodeNo, param, MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                }
                else
                {
                    UInt32 AccountNo = 0;
                    //调账获取账户信息
                    tagTPE_QueryGeneralAccountReq ReqAcc = new tagTPE_QueryGeneralAccountReq();
                    tagTPE_QueryResControl ResControl = new tagTPE_QueryResControl();
                    ReqAcc.SQL = "where CertCode = '" + CertCode.Trim() + "'";
                    ReqAcc.resflagName = 1;
                    ReqAcc.resflagCertCode = 1;
                    ReqAcc.resflagBalance = 1;
                    ReqAcc.resflagCardNo = 1;
                    ReqAcc.resflagCondition = 1;

                    int nRet = TPE_Class.TPE_QueryGeneralAccount(1, ref ReqAcc, out ResControl, 1);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "调账失败！ nRet=" + nRet.ToString();
                    }
                    else if (ResControl.ResRecCount == 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "帐户不存在！";
                    }
                    else if (ResControl.ResRecCount > 1)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "此工号对应帐户不唯一！";
                    }
                    else
                    {
                        tagTPE_GetAccountRes AccRes = new tagTPE_GetAccountRes();
                        unsafe
                        {
                            IntPtr buffer1 = (IntPtr)((Byte*)(ResControl.pRes));
                            AccRes = (tagTPE_GetAccountRes)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer1, typeof(tagTPE_GetAccountRes));
                            //try
                            //{
                            //    TPE_Class.TPE_Free(ref ResControl.pRes);
                            //} catch (Exception exxxx)
                            //{
                            //    CPublic.WriteLog("进入TPE_QueryFlowByAcc检查 " + exxxx.Message + exxxx.StackTrace);
                            //}
                            ResControl.pRes = null;
                        }
                        AccountNo = (UInt32)AccRes.AccountNo;
                    }

                    if (AccountNo != 0)
                    {
                        tagTPE_QueryFlowByCenterReq Req = new tagTPE_QueryFlowByCenterReq();
                        tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                        Req.FromCentralNo = 0;
                        Req.ToCentralNo = 0X7FFFFFFF;
                        Req.JoinCardHolder = new byte[24];
                        Req.OccurNode = new byte[128];
                        Req.TransType = new UInt32[32];
                        Req.RangeOccurTime = new byte[28];
                        Req.ReqFlag = 1;
                        Req.reqflagAccountNo = 1;
                        Req.AccountNo = AccountNo;
                        Req.reqflagRangeOccurTime = 1;
                        byte[] byDaya = System.Text.Encoding.Default.GetBytes(BeginTime);
                        Array.Copy(byDaya, 0, Req.RangeOccurTime, 0, 14);
                        byDaya = System.Text.Encoding.Default.GetBytes(EndTime);
                        Array.Copy(byDaya, 0, Req.RangeOccurTime, 14, 14);
                        //Req.ToCentralNo = 0x0FFFFFFF;
                        nRet = TPE_Class.TPE_QueryFlowByCenter(1, ref Req, out Res, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "nRet=" + nRet.ToString();
                        }
                        else
                        {
                            if (Res.ResRecCount == 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "ResRecCount=" + Res.ResRecCount.ToString();
                            }
                            else
                            {
                                tagTPE_CReturnObj Tpe_CRO;
                                TPE_CReturnObj cTpe_Cro;
                                IntPtr buffer = (IntPtr)((Byte*)(Res.pRes));
                                int Offset = 4;
                                int type = 0;
                                for (int i = 0; i < Res.ResRecCount; i++)
                                {
                                    type = Marshal.ReadInt32(new IntPtr(buffer.ToInt32() + Offset - 4));
                                    switch (type)
                                    {
                                        case 1: //开户
                                            tagTPE_QueryFlowRes_Open FlowRes_Open = new tagTPE_QueryFlowRes_Open();
                                            FlowRes_Open = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                            Tpe_CRO = new tagTPE_CReturnObj();
                                            Tpe_CRO.TransType = 1;
                                            Tpe_CRO.CenterNo = FlowRes_Open.CenterNo;
                                            Tpe_CRO.OccurNode = FlowRes_Open.OccurNode;
                                            Tpe_CRO.OccurIdNo = FlowRes_Open.OccurIdNo;
                                            Tpe_CRO.OccurTime = FlowRes_Open.OccurTime;
                                            Tpe_CRO.AccountNo = FlowRes_Open.AccountNo;
                                            Tpe_CRO.CardNo = FlowRes_Open.CardNo;
                                            Tpe_CRO.Balance = FlowRes_Open.Balance;
                                            Tpe_CRO.Condition = FlowRes_Open.Condition;
                                            Tpe_CRO.TransferLimit = FlowRes_Open.TransferLimit;
                                            Tpe_CRO.TransferMoney = FlowRes_Open.TransferMoney;
                                            cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                            listCRO.Add(cTpe_Cro);
                                            Offset += Marshal.SizeOf(FlowRes_Open);
                                            break;
                                        case 2: //撤户
                                            tagTPE_QueryFlowRes_Open FlowRes_Close = new tagTPE_QueryFlowRes_Open();
                                            FlowRes_Close = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                            Tpe_CRO = new tagTPE_CReturnObj();
                                            Tpe_CRO.TransType = 2;
                                            Tpe_CRO.CenterNo = FlowRes_Close.CenterNo;
                                            Tpe_CRO.OccurNode = FlowRes_Close.OccurNode;
                                            Tpe_CRO.OccurIdNo = FlowRes_Close.OccurIdNo;
                                            Tpe_CRO.OccurTime = FlowRes_Close.OccurTime;
                                            Tpe_CRO.AccountNo = FlowRes_Close.AccountNo;
                                            Tpe_CRO.CardNo = FlowRes_Close.CardNo;
                                            Tpe_CRO.Balance = FlowRes_Close.Balance;
                                            Tpe_CRO.Condition = FlowRes_Close.Condition;
                                            Tpe_CRO.TransferLimit = FlowRes_Close.TransferLimit;
                                            Tpe_CRO.TransferMoney = FlowRes_Close.TransferMoney;
                                            cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                            listCRO.Add(cTpe_Cro);
                                            Offset += Marshal.SizeOf(FlowRes_Close);
                                            break;
                                        case 3: //建立对应关系
                                            tagTPE_QueryFlowRes_BuildRelation FlowRes_Create = new tagTPE_QueryFlowRes_BuildRelation();
                                            FlowRes_Create = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                            Tpe_CRO = new tagTPE_CReturnObj();
                                            Tpe_CRO.TransType = 3;
                                            Tpe_CRO.CenterNo = FlowRes_Create.CenterNo;
                                            Tpe_CRO.OccurNode = FlowRes_Create.OccurNode;
                                            Tpe_CRO.OccurIdNo = FlowRes_Create.OccurIdNo;
                                            Tpe_CRO.OccurTime = FlowRes_Create.OccurTime;
                                            Tpe_CRO.AccountNo = FlowRes_Create.AccountNo;
                                            Tpe_CRO.CardNo = FlowRes_Create.CardNo;
                                            Tpe_CRO.JoinCardHolder = FlowRes_Create.JoinCardHolder;
                                            Tpe_CRO.JoinNode = FlowRes_Create.JoinNode;
                                            cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                            listCRO.Add(cTpe_Cro);
                                            Offset += Marshal.SizeOf(FlowRes_Create);
                                            break;
                                        case 4: //撤消对应
                                            tagTPE_QueryFlowRes_BuildRelation FlowRes_Drop = new tagTPE_QueryFlowRes_BuildRelation();
                                            FlowRes_Drop = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                            Tpe_CRO = new tagTPE_CReturnObj();
                                            Tpe_CRO.TransType = 4;
                                            Tpe_CRO.CenterNo = FlowRes_Drop.CenterNo;
                                            Tpe_CRO.OccurNode = FlowRes_Drop.OccurNode;
                                            Tpe_CRO.OccurIdNo = FlowRes_Drop.OccurIdNo;
                                            Tpe_CRO.OccurTime = FlowRes_Drop.OccurTime;
                                            Tpe_CRO.AccountNo = FlowRes_Drop.AccountNo;
                                            Tpe_CRO.CardNo = FlowRes_Drop.CardNo;
                                            Tpe_CRO.JoinCardHolder = FlowRes_Drop.JoinCardHolder;
                                            Tpe_CRO.JoinNode = FlowRes_Drop.JoinNode;
                                            cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                            listCRO.Add(cTpe_Cro);
                                            Offset += Marshal.SizeOf(FlowRes_Drop);
                                            break;
                                        case 5: //更改帐户信息
                                            tagTPE_QueryFlowRes_UpdateAccount FlowRes_Update = new tagTPE_QueryFlowRes_UpdateAccount();
                                            FlowRes_Update = (tagTPE_QueryFlowRes_UpdateAccount)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateAccount));
                                            Tpe_CRO = new tagTPE_CReturnObj();
                                            Tpe_CRO.TransType = 5;
                                            Tpe_CRO.CenterNo = FlowRes_Update.CenterNo;
                                            Tpe_CRO.OccurNode = FlowRes_Update.OccurNode;
                                            Tpe_CRO.OccurIdNo = FlowRes_Update.OccurIdNo;
                                            Tpe_CRO.OccurTime = FlowRes_Update.OccurTime;
                                            Tpe_CRO.AccountNo = FlowRes_Update.AccountNo;
                                            Tpe_CRO.CardNo = FlowRes_Update.CardNo;
                                            Tpe_CRO.TransferLimit = FlowRes_Update.TransferLimit;
                                            Tpe_CRO.TransferMoney = FlowRes_Update.TransferMoney;
                                            cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                            listCRO.Add(cTpe_Cro);
                                            Offset += Marshal.SizeOf(FlowRes_Update);
                                            //tagTPE_GetAccountReq ReqA = new tagTPE_GetAccountReq();
                                            //tagTPE_GetAccountRes ResA = new tagTPE_GetAccountRes();
                                            //ReqA.AccountNo = FlowRes_Update.AccountNo;
                                            //ReqA.resflagAccountNo = 1;     //帐号
                                            //ReqA.resflagCardNo = 1;        //卡号
                                            //ReqA.resflagCondition = 1;     //状态
                                            //ReqA.resflagBalance = 1;       //余额
                                            //ReqA.resflagName = 1;          //姓名
                                            //ReqA.resflagPersonID = 1;      //身份证号
                                            //ReqA.resflagPassword = 1;      //密码 
                                            //ReqA.resflagBirthday = 1;      //出生日期
                                            //ReqA.resflagDepart = 1;        //部门
                                            //ReqA.resflagIdenti = 1;        //身份
                                            //ReqA.resflagNation = 1;        //民族国籍
                                            //ReqA.resflagTel = 1;           //电话
                                            //int nRetA = TPE_Class.TPE_GetAccount(1, ref ReqA, out ResA, 1);
                                            break;
                                        case 6: //更改对应关系
                                            tagTPE_QueryFlowRes_UpdateRelation FlowRes_UpdateRelation = new tagTPE_QueryFlowRes_UpdateRelation();
                                            FlowRes_UpdateRelation = (tagTPE_QueryFlowRes_UpdateRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateRelation));
                                            Tpe_CRO = new tagTPE_CReturnObj();
                                            Tpe_CRO.TransType = 6;
                                            Tpe_CRO.CenterNo = FlowRes_UpdateRelation.CenterNo;
                                            Tpe_CRO.OccurNode = FlowRes_UpdateRelation.OccurNode;
                                            Tpe_CRO.OccurIdNo = FlowRes_UpdateRelation.OccurIdNo;
                                            Tpe_CRO.OccurTime = FlowRes_UpdateRelation.OccurTime;
                                            Tpe_CRO.AccountNo = FlowRes_UpdateRelation.AccountNo;
                                            Tpe_CRO.CardNo = FlowRes_UpdateRelation.CardNo;
                                            Tpe_CRO.JoinCardHolder = FlowRes_UpdateRelation.JoinCardHolder;
                                            Tpe_CRO.JoinNode = FlowRes_UpdateRelation.JoinNode;
                                            cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                            listCRO.Add(cTpe_Cro);
                                            Offset += Marshal.SizeOf(FlowRes_UpdateRelation);
                                            break;
                                        case 7: //余额变更, 不区分具体来源
                                        case 8: //余额变更, 由相关操作引发
                                        case 9: //余额变更, 存取款引发
                                        case 10: //余额变更, 由补助扣款引发
                                        case 11: //余额变更, 卡片交易引发
                                        case 12: //余额变更, 银行转帐引发 
                                        case 13: //余额变更, 通用缴费 
                                        case 14: //余额变更, 押金 
                                        case 15: //余额变更, 管理费 
                                        case 16: //余额变更, 手续费 
                                        case 17: //余额变更, 工本费 
                                        case 18: //余额变更,内部转出
                                        case 19: //余额变更,内部转入
                                            tagTPE_QueryFlowRes_Cost FlowRes_Cost = new tagTPE_QueryFlowRes_Cost();
                                            FlowRes_Cost = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Cost));
                                            Tpe_CRO = new tagTPE_CReturnObj();
                                            //Tpe_CRO.OrderID = new byte[16];
                                            Tpe_CRO.TransType = 7;
                                            Tpe_CRO.CenterNo = FlowRes_Cost.CenterNo;
                                            Tpe_CRO.OccurNode = FlowRes_Cost.OccurNode;
                                            Tpe_CRO.OccurIdNo = FlowRes_Cost.OccurIdNo;
                                            Tpe_CRO.OccurTime = FlowRes_Cost.OccurTime;
                                            Tpe_CRO.AccountNo = FlowRes_Cost.AccountNo;
                                            Tpe_CRO.CardNo = FlowRes_Cost.CardNo;
                                            Tpe_CRO.Balance = FlowRes_Cost.Balance;
                                            Tpe_CRO.JoinNode = FlowRes_Cost.JoinNode;
                                            Tpe_CRO.JoinCardHolder = FlowRes_Cost.JoinCardHolder;
                                            Tpe_CRO.TransMoney = FlowRes_Cost.TransMoney;
                                            Offset += Marshal.SizeOf(FlowRes_Cost);
                                            byte[] DataBuf = new byte[FlowRes_Cost.ExtendLen];
                                            Marshal.Copy(new IntPtr(buffer.ToInt32() + Offset), DataBuf, 0, (int)FlowRes_Cost.ExtendLen);
                                            string strMsg = "流水扩展信息长度" + FlowRes_Cost.ExtendLen.ToString() + "，内容";
                                            for (int m = 0; m < FlowRes_Cost.ExtendLen; m++)
                                            {
                                                strMsg += DataBuf[m].ToString("X2");
                                            }
                                            CPublic.WriteLog(strMsg);
                                            //HTEXTENDINFO tmpHTEXTENDINFO = new HTEXTENDINFO();
                                            //if (FlowRes_Cost.ExtendLen >= Marshal.SizeOf(tmpHTEXTENDINFO))
                                            //{
                                            //    tmpHTEXTENDINFO = (HTEXTENDINFO)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(HTEXTENDINFO));
                                            //    if (tmpHTEXTENDINFO.NodeType == 0X00030001)
                                            //    {
                                            //        tmpHTEXTENDINFO.OrderID.CopyTo(Tpe_CRO.OrderID, 0);
                                            //    }
                                            //}
                                            cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                            listCRO.Add(cTpe_Cro);
                                            Offset += (int)FlowRes_Cost.ExtendLen;
                                            break;
                                    }
                                    Offset += 4;
                                }
                                Res.pRes = null;
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.ListDate = listCRO;
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("按中心记帐号查询流水异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("按中心记帐号查询流水异常 ToJson:" + ex.Message);
            }
            return json;
        }
        /// <summary>
        /// 密码验证
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="AccountNo">帐号(卡号传入一项即可)</param>
        /// <param name="CardNo">卡号(帐号传入一项即可)</param>
        /// <param name="PassWord">密码</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        public string TPE_CheckPassword(string NodeNo, string AccountNo, string CardNo, string PassWord, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            string json = "";
            try
            {
                int nodeNo; int accNo; int cardNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(AccountNo) && string.IsNullOrEmpty(CardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo/CardNo(至少传入一项)]";
                }
                else if (!string.IsNullOrEmpty(AccountNo) && !int.TryParse(AccountNo, out accNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo(类型Int)]";
                }
                else if (!string.IsNullOrEmpty(CardNo) && !int.TryParse(CardNo, out cardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[CardNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(PassWord))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[PassWord]";
                }
                else
                {
                    string param = "";
                    if (!string.IsNullOrEmpty(AccountNo))
                    {
                        param = AccountNo;
                    }
                    else if (string.IsNullOrEmpty(AccountNo) && !string.IsNullOrEmpty(CardNo))
                    {
                        param = CardNo;
                    }
                    else if (!string.IsNullOrEmpty(AccountNo) && !string.IsNullOrEmpty(CardNo))
                    {
                        param = AccountNo + "$" + CardNo;
                    }
                    if (CheckNode(NodeNo, param + "$" + PassWord, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param + "$" + PassWord, MAC)];
                    }
                    else
                    {
                        tagTPE_GetAccountReq Req = new tagTPE_GetAccountReq();
                        tagTPE_GetAccountRes Res = new tagTPE_GetAccountRes();
                        Req.reqflagPassword = '1';
                        if (!string.IsNullOrEmpty(AccountNo))
                        {
                            Req.AccountNo = System.Convert.ToUInt32(AccountNo);
                        }
                        if (!string.IsNullOrEmpty(CardNo))
                        {
                            Req.CardNo = System.Convert.ToInt32(CardNo);
                        }
                        Req.Password = new byte[8];
                        var tmp = System.Text.Encoding.ASCII.GetBytes(PassWord);
                        Array.Copy(tmp, Req.Password, tmp.Length > 8 ? 8 : tmp.Length);
                        int nRet = TPE_Class.TPE_GetAccount(1, ref Req, out Res, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "nRet=" + nRet.ToString();
                        }
                        else
                        {
                            if (Res.RetValue != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "RetValue=" + Res.RetValue.ToString();
                            }
                            else
                            {
                                TPE_GetAccountRes Ctpe_Res = new TPE_GetAccountRes(Res);
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.Data = Ctpe_Res;
                            }
                        }
                    }
                }

            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("验证密码 异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("验证密码 异常 ToJson:" + ex.Message);
            }
            return json;
        }

        ////////!!!!!!!!!!!!!!!!!!!!
        /// <summary>
        /// 按标准条件查询帐户
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC</param>
        /// <param name="BeginNo">起始位置</param>
        /// <param name="EndNo">结束位置</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_QueryStdAccount(string NodeNo, string BeginNo, string EndNo, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            List<TPE_GetAccountRes> listRes = new List<TPE_GetAccountRes>();
            string json = "";
            try
            {
                int nodeNo; int begNo; int endNo;
                string param = BeginNo + "$" + EndNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(BeginNo) || !int.TryParse(BeginNo, out begNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[BeginNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(EndNo) || !int.TryParse(EndNo, out endNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[EndNo(类型Int)]";
                }
                else if (CheckNode(NodeNo, param, MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                }
                else
                {
                    tagTPE_QueryStdAccountReq Req = new tagTPE_QueryStdAccountReq();
                    tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                    Req.AccountNoRange = new int[] { Convert.ToInt32(BeginNo), Convert.ToInt32(EndNo) };
                    Req.reqflagAccountNoRange = 1;//帐号范围
                    Req.resflagCardNo = 1;        //卡号
                    Req.resflagCondition = 1;     //状态
                    Req.resflagBalance = 1;       //余额
                    Req.resflagCreateTime = 1;    //开户时间 
                    Req.resflagExpireDate = 1;    //有效期
                    Req.resflagName = 1;          //姓名
                    Req.resflagPersonID = 0;      //身份证号
                    Req.resflagPassword = 0;      //密码 
                    Req.resflagAccessControl = 0; //访问控制,
                    Req.resflagBirthday = 0;      //出生日期
                    Req.resflagDepart = 1;        //部门
                    Req.resflagIdenti = 1;        //身份
                    Req.resflagNation = 0;        //民族国籍
                    Req.resflagCertType = 0;      //证件类型
                    Req.resflagCertCode = 0;      //证件号码
                    Req.resflagCreditCardNo = 0;  //银行卡号
                    Req.resflagTransferLimit = 0; //转帐限额 
                    Req.resflagTransferMoney = 0; //转帐金额
                    Req.resflagTel = 0;           //电话
                    Req.resflagEmail = 0;         //电邮
                    Req.resflagPostalCode = 0;    //邮政编码
                    Req.resflagPostalAddr = 0;    //通信地址
                    Req.resflagFile = 0;          //文件;
                    Req.resflagComment = 0;       //注释
                    Req.resflagExtend = 0;        //扩展
                    Req.resflagUpdateTime = 0;    //最后更新日期
                    int nRet = TPE_Class.TPE_QueryStdAccount(1, ref Req, out Res, 1);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "nRet=" + nRet.ToString();
                    }
                    else
                    {
                        if (Res.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "ResRecCount=" + Res.ResRecCount.ToString();
                        }
                        else
                        {
                            tagTPE_GetAccountRes AccRes = new tagTPE_GetAccountRes();
                            TPE_GetAccountRes tpe_GetAccRes;
                            IntPtr buffer;
                            for (int i = 0; i < Res.ResRecCount; i++)
                            {
                                buffer = (IntPtr)((Byte*)(Res.pRes) + i * System.Runtime.InteropServices.Marshal.SizeOf(AccRes));
                                AccRes = (tagTPE_GetAccountRes)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer, typeof(tagTPE_GetAccountRes));
                                tpe_GetAccRes = new TPE_GetAccountRes(AccRes);
                                listRes.Add(tpe_GetAccRes);
                            }
                            Res.pRes = null;
                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.ListDate = listRes;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg += "按标准条件查询帐户异常：" + e.Message;
                CPublic.WriteLog("按标准条件查询帐户异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                retRes.Msg += "按标准条件查询帐户异常 ToJson:" + ex.Message;
                CPublic.WriteLog("按标准条件查询帐户异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 按中心序号查询流水
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="FromCentralNo">开始位置</param>
        /// <param name="ToCentralNo">结束位置</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_QueryFlowByCenter(string NodeNo, string FromCentralNo, string ToCentralNo, string MAC)
        {
            CReturnCReturnObj retRes = new CReturnCReturnObj();
            List<TPE_CReturnObj> listCRO = new List<TPE_CReturnObj>();
            string json = "";
            try
            {
                int nodeNo; int fromNo; int toNo;
                string param = FromCentralNo + "$" + ToCentralNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(FromCentralNo) || !int.TryParse(FromCentralNo, out fromNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[FromCentralNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(ToCentralNo) || !int.TryParse(ToCentralNo, out toNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[ToCentralNo(类型Int)]";
                }
                else if (CheckNode(NodeNo, param, MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                }
                else
                {

                    tagTPE_QueryFlowByCenterReq Req = new tagTPE_QueryFlowByCenterReq();
                    tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                    Req.FromCentralNo = UInt32.Parse(FromCentralNo);
                    Req.ToCentralNo = UInt32.Parse(ToCentralNo);
                    Req.JoinCardHolder = new byte[24];
                    Req.OccurNode = new byte[128];
                    Req.TransType = new UInt32[32];
                    Req.RangeOccurTime = new byte[28];
                    Req.ReqFlag = 0;
                    //Req.ToCentralNo = 0x0FFFFFFF;
                    int nRet = TPE_Class.TPE_QueryFlowByCenter(1, ref Req, out Res, 1);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "nRet=" + nRet.ToString();
                    }
                    else
                    {
                        if (Res.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "ResRecCount=" + Res.ResRecCount.ToString();
                        }
                        else
                        {
                            tagTPE_CReturnObj Tpe_CRO;
                            TPE_CReturnObj cTpe_Cro;
                            IntPtr buffer = (IntPtr)((Byte*)(Res.pRes));
                            int Offset = 4;
                            int type = 0;
                            for (int i = 0; i < Res.ResRecCount; i++)
                            {
                                type = Marshal.ReadInt32(new IntPtr(buffer.ToInt32() + Offset - 4));
                                switch (type)
                                {
                                    case 1: //开户
                                        tagTPE_QueryFlowRes_Open FlowRes_Open = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Open = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 1;
                                        Tpe_CRO.CenterNo = FlowRes_Open.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Open.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Open.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Open.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Open.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Open.CardNo;
                                        Tpe_CRO.Balance = FlowRes_Open.Balance;
                                        Tpe_CRO.Condition = FlowRes_Open.Condition;
                                        Tpe_CRO.TransferLimit = FlowRes_Open.TransferLimit;
                                        Tpe_CRO.TransferMoney = FlowRes_Open.TransferMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Open);
                                        break;
                                    case 2: //撤户
                                        tagTPE_QueryFlowRes_Open FlowRes_Close = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Close = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 2;
                                        Tpe_CRO.CenterNo = FlowRes_Close.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Close.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Close.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Close.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Close.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Close.CardNo;
                                        Tpe_CRO.Balance = FlowRes_Close.Balance;
                                        Tpe_CRO.Condition = FlowRes_Close.Condition;
                                        Tpe_CRO.TransferLimit = FlowRes_Close.TransferLimit;
                                        Tpe_CRO.TransferMoney = FlowRes_Close.TransferMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Close);
                                        break;
                                    case 3: //建立对应关系
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Create = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Create = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 3;
                                        Tpe_CRO.CenterNo = FlowRes_Create.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Create.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Create.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Create.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Create.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Create.CardNo;
                                        Tpe_CRO.JoinCardHolder = FlowRes_Create.JoinCardHolder;
                                        Tpe_CRO.JoinNode = FlowRes_Create.JoinNode;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Create);
                                        break;
                                    case 4: //撤消对应
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Drop = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Drop = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 4;
                                        Tpe_CRO.CenterNo = FlowRes_Drop.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Drop.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Drop.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Drop.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Drop.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Drop.CardNo;
                                        Tpe_CRO.JoinCardHolder = FlowRes_Drop.JoinCardHolder;
                                        Tpe_CRO.JoinNode = FlowRes_Drop.JoinNode;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Drop);
                                        break;
                                    case 5: //更改帐户信息
                                        tagTPE_QueryFlowRes_UpdateAccount FlowRes_Update = new tagTPE_QueryFlowRes_UpdateAccount();
                                        FlowRes_Update = (tagTPE_QueryFlowRes_UpdateAccount)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateAccount));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 5;
                                        Tpe_CRO.CenterNo = FlowRes_Update.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Update.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Update.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Update.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Update.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Update.CardNo;
                                        Tpe_CRO.TransferLimit = FlowRes_Update.TransferLimit;
                                        Tpe_CRO.TransferMoney = FlowRes_Update.TransferMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Update);
                                        //tagTPE_GetAccountReq ReqA = new tagTPE_GetAccountReq();
                                        //tagTPE_GetAccountRes ResA = new tagTPE_GetAccountRes();
                                        //ReqA.AccountNo = FlowRes_Update.AccountNo;
                                        //ReqA.resflagAccountNo = 1;     //帐号
                                        //ReqA.resflagCardNo = 1;        //卡号
                                        //ReqA.resflagCondition = 1;     //状态
                                        //ReqA.resflagBalance = 1;       //余额
                                        //ReqA.resflagName = 1;          //姓名
                                        //ReqA.resflagPersonID = 1;      //身份证号
                                        //ReqA.resflagPassword = 1;      //密码 
                                        //ReqA.resflagBirthday = 1;      //出生日期
                                        //ReqA.resflagDepart = 1;        //部门
                                        //ReqA.resflagIdenti = 1;        //身份
                                        //ReqA.resflagNation = 1;        //民族国籍
                                        //ReqA.resflagTel = 1;           //电话
                                        //int nRetA = TPE_Class.TPE_GetAccount(1, ref ReqA, out ResA, 1);
                                        break;
                                    case 6: //更改对应关系
                                        tagTPE_QueryFlowRes_UpdateRelation FlowRes_UpdateRelation = new tagTPE_QueryFlowRes_UpdateRelation();
                                        FlowRes_UpdateRelation = (tagTPE_QueryFlowRes_UpdateRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateRelation));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 6;
                                        Tpe_CRO.CenterNo = FlowRes_UpdateRelation.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_UpdateRelation.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_UpdateRelation.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_UpdateRelation.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_UpdateRelation.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_UpdateRelation.CardNo;
                                        Tpe_CRO.JoinCardHolder = FlowRes_UpdateRelation.JoinCardHolder;
                                        Tpe_CRO.JoinNode = FlowRes_UpdateRelation.JoinNode;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_UpdateRelation);
                                        break;
                                    case 7: //余额变更, 不区分具体来源
                                    case 8: //余额变更, 由相关操作引发
                                    case 9: //余额变更, 存取款引发
                                    case 10: //余额变更, 由补助扣款引发
                                    case 11: //余额变更, 卡片交易引发
                                    case 12: //余额变更, 银行转帐引发 
                                    case 13: //余额变更, 通用缴费 
                                    case 14: //余额变更, 押金 
                                    case 15: //余额变更, 管理费 
                                    case 16: //余额变更, 手续费 
                                    case 17: //余额变更, 工本费 
                                    case 18: //余额变更,内部转出
                                    case 19: //余额变更,内部转入
                                        tagTPE_QueryFlowRes_Cost FlowRes_Cost = new tagTPE_QueryFlowRes_Cost();
                                        FlowRes_Cost = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Cost));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 7;
                                        Tpe_CRO.CenterNo = FlowRes_Cost.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Cost.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Cost.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Cost.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Cost.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Cost.CardNo;
                                        Tpe_CRO.Balance = FlowRes_Cost.Balance;
                                        Tpe_CRO.JoinNode = FlowRes_Cost.JoinNode;
                                        Tpe_CRO.JoinCardHolder = FlowRes_Cost.JoinCardHolder;
                                        Tpe_CRO.TransMoney = FlowRes_Cost.TransMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Cost);
                                        Offset += (int)FlowRes_Cost.ExtendLen;
                                        break;
                                }
                                Offset += 4;
                            }
                            Res.pRes = null;
                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.ListDate = listCRO;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("按中心记帐号查询流水异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("按中心记帐号查询流水异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 按发生序号查询流水
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="FromCentralNo">开始位置</param>
        /// <param name="ToCentralNo">结束位置</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        unsafe int QueryOccurByCenter(string OccurNodeNo, int OccurNo)
        {
            CReturnCReturnObj retRes = new CReturnCReturnObj();
            int json = 0;
            try
            {
                tagTPE_QueryFlowBySQLReq Req = new tagTPE_QueryFlowBySQLReq();
                tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                String tmpSQL = " WHERE OccurNode = '" + OccurNodeNo + "' AND OccurTick = '" + OccurNo.ToString() + "'";
                Req.SQL = new byte[4096];
                Array.Copy(System.Text.Encoding.Default.GetBytes(tmpSQL), 0, Req.SQL, 0, System.Text.Encoding.Default.GetBytes(tmpSQL).Length);
                int nRet = TPE_Class.TPE_QueryFlowBySQL(1, ref Req, out Res, 1);
                if (nRet != 0)
                {
                    json = -1;
                }
                else
                {
                    if (Res.ResRecCount == 0)
                    {
                        json = -2;
                    }
                    else
                    {
                        if (Res.ResRecCount != 1) { return -3; }
                        IntPtr buffer = (IntPtr)((Byte*)(Res.pRes));
                        int type = 0;
                        for (int i = 0; i < Res.ResRecCount; i++)
                        {
                            type = Marshal.ReadInt32(new IntPtr(buffer.ToInt32()));
                            try
                            {
                                switch (type)
                                {
                                    case 1: //开户
                                        tagTPE_QueryFlowRes_Open FlowRes_Open = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Open = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_Open));
                                        json = int.Parse(FlowRes_Open.CenterNo.ToString());
                                        break;
                                    case 2: //撤户
                                        tagTPE_QueryFlowRes_Open FlowRes_Close = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Close = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_Open));
                                        json = int.Parse(FlowRes_Close.CenterNo.ToString());
                                        break;
                                    case 3: //建立对应关系
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Create = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Create = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        json = int.Parse(FlowRes_Create.CenterNo.ToString());
                                        break;
                                    case 4: //撤消对应
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Drop = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Drop = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        json = int.Parse(FlowRes_Drop.CenterNo.ToString());
                                        break;
                                    case 5: //更改帐户信息
                                        tagTPE_QueryFlowRes_UpdateAccount FlowRes_Update = new tagTPE_QueryFlowRes_UpdateAccount();
                                        FlowRes_Update = (tagTPE_QueryFlowRes_UpdateAccount)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_UpdateAccount));
                                        json = int.Parse(FlowRes_Update.CenterNo.ToString());
                                        break;
                                    case 6: //更改对应关系
                                        tagTPE_QueryFlowRes_UpdateRelation FlowRes_UpdateRelation = new tagTPE_QueryFlowRes_UpdateRelation();
                                        FlowRes_UpdateRelation = (tagTPE_QueryFlowRes_UpdateRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_UpdateRelation));
                                        json = int.Parse(FlowRes_UpdateRelation.CenterNo.ToString());
                                        break;
                                    case 7: //余额变更, 不区分具体来源
                                    case 8: //余额变更, 由相关操作引发
                                    case 9: //余额变更, 存取款引发
                                    case 10: //余额变更, 由补助扣款引发
                                    case 11: //余额变更, 卡片交易引发
                                    case 12: //余额变更, 银行转帐引发 
                                    case 13: //余额变更, 通用缴费 
                                    case 14: //余额变更, 押金 
                                    case 15: //余额变更, 管理费 
                                    case 16: //余额变更, 手续费 
                                    case 17: //余额变更, 工本费 
                                    case 18: //余额变更,内部转出
                                    case 19: //余额变更,内部转入
                                        tagTPE_QueryFlowRes_Cost FlowRes_Cost = new tagTPE_QueryFlowRes_Cost();
                                        FlowRes_Cost = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_Cost));
                                        json = int.Parse(FlowRes_Cost.CenterNo.ToString());
                                        break;
                                }
                            }
                            catch (Exception)
                            {
                                json = -998;
                            }
                        }
                     }
                }
            }
            catch (Exception)
            {
                json = -999;
            }
            return json;
        }
        unsafe uint QueryOccurByCenterUINT(string OccurNodeNo, uint OccurNo)
        {
            CReturnCReturnObj retRes = new CReturnCReturnObj();
            uint json = 0;
            try
            {
                tagTPE_QueryFlowBySQLReq Req = new tagTPE_QueryFlowBySQLReq();
                tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                String tmpSQL = " WHERE OccurNode = '" + OccurNodeNo + "' AND OccurTick = '" + OccurNo.ToString() + "'";
                Req.SQL = new byte[4096];
                Array.Copy(System.Text.Encoding.Default.GetBytes(tmpSQL), 0, Req.SQL, 0, System.Text.Encoding.Default.GetBytes(tmpSQL).Length);
                int nRet = TPE_Class.TPE_QueryFlowBySQL(1, ref Req, out Res, 1);
                if (nRet != 0)
                {
                    return uint.MaxValue - 1;
                }
                else
                {
                    if (Res.ResRecCount == 0)
                    {
                        return uint.MaxValue - 2;
                    }
                    else
                    {
                        if (Res.ResRecCount != 1) { return uint.MaxValue - 3; }
                        IntPtr buffer = (IntPtr)((Byte*)(Res.pRes));
                        int type = 0;
                        for (int i = 0; i < Res.ResRecCount; i++)
                        {
                            type = Marshal.ReadInt32(new IntPtr(buffer.ToInt32()));
                            try
                            {
                                switch (type)
                                {
                                    case 1: //开户
                                        tagTPE_QueryFlowRes_Open FlowRes_Open = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Open = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_Open));
                                        json = FlowRes_Open.CenterNo;
                                        break;
                                    case 2: //撤户
                                        tagTPE_QueryFlowRes_Open FlowRes_Close = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Close = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_Open));
                                        json = FlowRes_Close.CenterNo;
                                        break;
                                    case 3: //建立对应关系
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Create = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Create = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        json = FlowRes_Create.CenterNo;
                                        break;
                                    case 4: //撤消对应
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Drop = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Drop = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        json = FlowRes_Drop.CenterNo;
                                        break;
                                    case 5: //更改帐户信息
                                        tagTPE_QueryFlowRes_UpdateAccount FlowRes_Update = new tagTPE_QueryFlowRes_UpdateAccount();
                                        FlowRes_Update = (tagTPE_QueryFlowRes_UpdateAccount)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_UpdateAccount));
                                        json = FlowRes_Update.CenterNo;
                                        break;
                                    case 6: //更改对应关系
                                        tagTPE_QueryFlowRes_UpdateRelation FlowRes_UpdateRelation = new tagTPE_QueryFlowRes_UpdateRelation();
                                        FlowRes_UpdateRelation = (tagTPE_QueryFlowRes_UpdateRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_UpdateRelation));
                                        json = FlowRes_UpdateRelation.CenterNo;
                                        break;
                                    case 7: //余额变更, 不区分具体来源
                                    case 8: //余额变更, 由相关操作引发
                                    case 9: //余额变更, 存取款引发
                                    case 10: //余额变更, 由补助扣款引发
                                    case 11: //余额变更, 卡片交易引发
                                    case 12: //余额变更, 银行转帐引发 
                                    case 13: //余额变更, 通用缴费 
                                    case 14: //余额变更, 押金 
                                    case 15: //余额变更, 管理费 
                                    case 16: //余额变更, 手续费 
                                    case 17: //余额变更, 工本费 
                                    case 18: //余额变更,内部转出
                                    case 19: //余额变更,内部转入
                                        tagTPE_QueryFlowRes_Cost FlowRes_Cost = new tagTPE_QueryFlowRes_Cost();
                                        FlowRes_Cost = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + 4), typeof(tagTPE_QueryFlowRes_Cost));
                                        json = FlowRes_Cost.CenterNo;
                                        break;
                                }
                            }
                            catch (Exception)
                            {
                                return uint.MaxValue - 0; ;
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                return uint.MaxValue - 4; ;
            }
            return json;
        }

        /// <summary>
        /// 按发生序号查询流水
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="FromCentralNo">开始位置</param>
        /// <param name="ToCentralNo">结束位置</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_QueryFlowByOccur(string NodeNo, string OccurNodeNo, string FromOccurNo, string ToOccurNo, string MAC)
        {
            CReturnCReturnObj retRes = new CReturnCReturnObj();
            List<TPE_CReturnObj> listCRO = new List<TPE_CReturnObj>();
            string json = "";
            try
            {
                int nodeNo; int occurNodeNo; int fromNo; int toNo;
                string param = OccurNodeNo + "$" + FromOccurNo + "$" + ToOccurNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                if (string.IsNullOrEmpty(OccurNodeNo) || !int.TryParse(OccurNodeNo, out occurNodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[OccurNodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(FromOccurNo) || !int.TryParse(FromOccurNo, out fromNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[FromCentralNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(ToOccurNo) || !int.TryParse(ToOccurNo, out toNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[ToCentralNo(类型Int)]";
                }
                else if (CheckNode(NodeNo, param, MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                }
                else
                {

                    tagTPE_QueryFlowBySQLReq Req = new tagTPE_QueryFlowBySQLReq();
                    tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                    //Req.ToCentralNo = 0x0FFFFFFF;
                    String tmpSQL = " WHERE OccurNode = '" + OccurNodeNo.ToString() + "' AND OccurTick BETWEEN '" + FromOccurNo.ToString() + "' AND '" + ToOccurNo.ToString() + "'";
                    Req.SQL = new byte[4096];
                    Array.Copy(System.Text.Encoding.Default.GetBytes(tmpSQL), 0, Req.SQL, 0, System.Text.Encoding.Default.GetBytes(tmpSQL).Length);
                    int nRet = TPE_Class.TPE_QueryFlowBySQL(1, ref Req, out Res, 1);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "nRet=" + nRet.ToString();
                    }
                    else
                    {
                        if (Res.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "ResRecCount=" + Res.ResRecCount.ToString();
                        }
                        else
                        {
                            tagTPE_CReturnObj Tpe_CRO;
                            TPE_CReturnObj cTpe_Cro;
                            IntPtr buffer = (IntPtr)((Byte*)(Res.pRes));
                            int Offset = 4;
                            int type = 0;
                            for (int i = 0; i < Res.ResRecCount; i++)
                            {
                                type = Marshal.ReadInt32(new IntPtr(buffer.ToInt32() + Offset - 4));
                                switch (type)
                                {
                                    case 1: //开户
                                        tagTPE_QueryFlowRes_Open FlowRes_Open = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Open = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 1;
                                        Tpe_CRO.CenterNo = FlowRes_Open.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Open.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Open.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Open.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Open.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Open.CardNo;
                                        Tpe_CRO.Balance = FlowRes_Open.Balance;
                                        Tpe_CRO.Condition = FlowRes_Open.Condition;
                                        Tpe_CRO.TransferLimit = FlowRes_Open.TransferLimit;
                                        Tpe_CRO.TransferMoney = FlowRes_Open.TransferMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Open);
                                        break;
                                    case 2: //撤户
                                        tagTPE_QueryFlowRes_Open FlowRes_Close = new tagTPE_QueryFlowRes_Open();
                                        FlowRes_Close = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 2;
                                        Tpe_CRO.CenterNo = FlowRes_Close.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Close.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Close.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Close.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Close.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Close.CardNo;
                                        Tpe_CRO.Balance = FlowRes_Close.Balance;
                                        Tpe_CRO.Condition = FlowRes_Close.Condition;
                                        Tpe_CRO.TransferLimit = FlowRes_Close.TransferLimit;
                                        Tpe_CRO.TransferMoney = FlowRes_Close.TransferMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Close);
                                        break;
                                    case 3: //建立对应关系
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Create = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Create = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 3;
                                        Tpe_CRO.CenterNo = FlowRes_Create.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Create.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Create.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Create.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Create.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Create.CardNo;
                                        Tpe_CRO.JoinCardHolder = FlowRes_Create.JoinCardHolder;
                                        Tpe_CRO.JoinNode = FlowRes_Create.JoinNode;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Create);
                                        break;
                                    case 4: //撤消对应
                                        tagTPE_QueryFlowRes_BuildRelation FlowRes_Drop = new tagTPE_QueryFlowRes_BuildRelation();
                                        FlowRes_Drop = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 4;
                                        Tpe_CRO.CenterNo = FlowRes_Drop.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Drop.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Drop.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Drop.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Drop.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Drop.CardNo;
                                        Tpe_CRO.JoinCardHolder = FlowRes_Drop.JoinCardHolder;
                                        Tpe_CRO.JoinNode = FlowRes_Drop.JoinNode;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Drop);
                                        break;
                                    case 5: //更改帐户信息
                                        tagTPE_QueryFlowRes_UpdateAccount FlowRes_Update = new tagTPE_QueryFlowRes_UpdateAccount();
                                        FlowRes_Update = (tagTPE_QueryFlowRes_UpdateAccount)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateAccount));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 5;
                                        Tpe_CRO.CenterNo = FlowRes_Update.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Update.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Update.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Update.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Update.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Update.CardNo;
                                        Tpe_CRO.TransferLimit = FlowRes_Update.TransferLimit;
                                        Tpe_CRO.TransferMoney = FlowRes_Update.TransferMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Update);
                                        //tagTPE_GetAccountReq ReqA = new tagTPE_GetAccountReq();
                                        //tagTPE_GetAccountRes ResA = new tagTPE_GetAccountRes();
                                        //ReqA.AccountNo = FlowRes_Update.AccountNo;
                                        //ReqA.resflagAccountNo = 1;     //帐号
                                        //ReqA.resflagCardNo = 1;        //卡号
                                        //ReqA.resflagCondition = 1;     //状态
                                        //ReqA.resflagBalance = 1;       //余额
                                        //ReqA.resflagName = 1;          //姓名
                                        //ReqA.resflagPersonID = 1;      //身份证号
                                        //ReqA.resflagPassword = 1;      //密码 
                                        //ReqA.resflagBirthday = 1;      //出生日期
                                        //ReqA.resflagDepart = 1;        //部门
                                        //ReqA.resflagIdenti = 1;        //身份
                                        //ReqA.resflagNation = 1;        //民族国籍
                                        //ReqA.resflagTel = 1;           //电话
                                        //int nRetA = TPE_Class.TPE_GetAccount(1, ref ReqA, out ResA, 1);
                                        break;
                                    case 6: //更改对应关系
                                        tagTPE_QueryFlowRes_UpdateRelation FlowRes_UpdateRelation = new tagTPE_QueryFlowRes_UpdateRelation();
                                        FlowRes_UpdateRelation = (tagTPE_QueryFlowRes_UpdateRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateRelation));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 6;
                                        Tpe_CRO.CenterNo = FlowRes_UpdateRelation.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_UpdateRelation.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_UpdateRelation.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_UpdateRelation.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_UpdateRelation.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_UpdateRelation.CardNo;
                                        Tpe_CRO.JoinCardHolder = FlowRes_UpdateRelation.JoinCardHolder;
                                        Tpe_CRO.JoinNode = FlowRes_UpdateRelation.JoinNode;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_UpdateRelation);
                                        break;
                                    case 7: //余额变更, 不区分具体来源
                                    case 8: //余额变更, 由相关操作引发
                                    case 9: //余额变更, 存取款引发
                                    case 10: //余额变更, 由补助扣款引发
                                    case 11: //余额变更, 卡片交易引发
                                    case 12: //余额变更, 银行转帐引发 
                                    case 13: //余额变更, 通用缴费 
                                    case 14: //余额变更, 押金 
                                    case 15: //余额变更, 管理费 
                                    case 16: //余额变更, 手续费 
                                    case 17: //余额变更, 工本费 
                                    case 18: //余额变更,内部转出
                                    case 19: //余额变更,内部转入
                                        tagTPE_QueryFlowRes_Cost FlowRes_Cost = new tagTPE_QueryFlowRes_Cost();
                                        FlowRes_Cost = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Cost));
                                        Tpe_CRO = new tagTPE_CReturnObj();
                                        Tpe_CRO.TransType = 7;
                                        Tpe_CRO.CenterNo = FlowRes_Cost.CenterNo;
                                        Tpe_CRO.OccurNode = FlowRes_Cost.OccurNode;
                                        Tpe_CRO.OccurIdNo = FlowRes_Cost.OccurIdNo;
                                        Tpe_CRO.OccurTime = FlowRes_Cost.OccurTime;
                                        Tpe_CRO.AccountNo = FlowRes_Cost.AccountNo;
                                        Tpe_CRO.CardNo = FlowRes_Cost.CardNo;
                                        Tpe_CRO.Balance = FlowRes_Cost.Balance;
                                        Tpe_CRO.JoinNode = FlowRes_Cost.JoinNode;
                                        Tpe_CRO.JoinCardHolder = FlowRes_Cost.JoinCardHolder;
                                        Tpe_CRO.TransMoney = FlowRes_Cost.TransMoney;
                                        cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                        listCRO.Add(cTpe_Cro);
                                        Offset += Marshal.SizeOf(FlowRes_Cost);
                                        Offset += (int)FlowRes_Cost.ExtendLen;
                                        break;
                                }
                                Offset += 4;
                            }
                            Res.pRes = null;
                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.ListDate = listCRO;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("按中心记帐号查询流水异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("按中心记帐号查询流水异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 按学工号查询流水
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="CertCode">学工号</param>
        /// <param name="FromCentralNo">开始位置</param>
        /// <param name="ToCentralNo">结束位置</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_QueryFlowByAccount(string NodeNo, string AccountNo, string BeginTime, string EndTime, string MAC)
        {
            CPublic.WriteLog("进入TPE_QueryFlowByAcc CertCode = " + AccountNo + ";BeginTime = " + BeginTime + ";EndTime = " + EndTime);
            CReturnCReturnObj retRes = new CReturnCReturnObj();
            List<TPE_CReturnObj> listCRO = new List<TPE_CReturnObj>();
            string json = "";
            try
            {
                int nodeNo;
                string param = AccountNo + "$" + BeginTime + "$" + EndTime;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg += "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg += "请传入有效参数[MAC]";
                }
                else if (CheckNode(NodeNo, param, MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg += "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                }
                else
                {
                    //调账获取账户信息
                    tagTPE_GetAccountReq ReqAcc = new tagTPE_GetAccountReq();
                    tagTPE_GetAccountRes ResAcc = new tagTPE_GetAccountRes();
                    if (!string.IsNullOrEmpty(AccountNo))
                    {
                        ReqAcc.AccountNo = System.Convert.ToUInt32(AccountNo);
                    }
                    ReqAcc.resflagName = 1;
                    ReqAcc.resflagCertCode = 1;
                    ReqAcc.resflagBalance = 1;
                    ReqAcc.resflagCardNo = 1;
                    ReqAcc.resflagCondition = 1;

                    UInt32 AccountNo_get = 0;
                    int nRet = TPE_Class.TPE_GetAccount(1, ref ReqAcc, out ResAcc, 1);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg += "调账失败！ nRet=" + nRet.ToString();
                    }
                    else
                    {
                        AccountNo_get = (UInt32)ResAcc.AccountNo;

                        if (AccountNo_get != 0)
                        {
                            tagTPE_QueryFlowByCenterReq Req = new tagTPE_QueryFlowByCenterReq();
                            tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                            Req.FromCentralNo = 0;
                            Req.ToCentralNo = 0X7FFFFFFF;
                            Req.JoinCardHolder = new byte[24];
                            Req.OccurNode = new byte[128];
                            Req.TransType = new UInt32[32];
                            Req.RangeOccurTime = new byte[28];
                            Req.ReqFlag = 1;
                            Req.reqflagAccountNo = 1;
                            Req.AccountNo = AccountNo_get;
                            Req.reqflagRangeOccurTime = 1;
                            byte[] byDaya = System.Text.Encoding.Default.GetBytes(BeginTime);
                            Array.Copy(byDaya, 0, Req.RangeOccurTime, 0, 14);
                            byDaya = System.Text.Encoding.Default.GetBytes(EndTime);
                            Array.Copy(byDaya, 0, Req.RangeOccurTime, 14, 14);
                            //Req.ToCentralNo = 0x0FFFFFFF;
                            nRet = TPE_Class.TPE_QueryFlowByCenter(1, ref Req, out Res, 1);
                            if (nRet != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg += "nRet=" + nRet.ToString();
                            }
                            else
                            {
                                if (Res.ResRecCount == 0)
                                {
                                    retRes.Result = "error";
                                    retRes.Msg += "ResRecCount=" + Res.ResRecCount.ToString();
                                }
                                else
                                {
                                    tagTPE_CReturnObj Tpe_CRO;
                                    TPE_CReturnObj cTpe_Cro;
                                    IntPtr buffer = (IntPtr)((Byte*)(Res.pRes));
                                    int Offset = 4;
                                    int type = 0;
                                    for (int i = 0; i < Res.ResRecCount; i++)
                                    {
                                        type = Marshal.ReadInt32(new IntPtr(buffer.ToInt32() + Offset - 4));
                                        switch (type)
                                        {
                                            case 1: //开户
                                                tagTPE_QueryFlowRes_Open FlowRes_Open = new tagTPE_QueryFlowRes_Open();
                                                FlowRes_Open = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 1;
                                                Tpe_CRO.CenterNo = FlowRes_Open.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Open.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Open.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Open.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_Open.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Open.CardNo;
                                                Tpe_CRO.Balance = FlowRes_Open.Balance;
                                                Tpe_CRO.Condition = FlowRes_Open.Condition;
                                                Tpe_CRO.TransferLimit = FlowRes_Open.TransferLimit;
                                                Tpe_CRO.TransferMoney = FlowRes_Open.TransferMoney;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Open);
                                                break;
                                            case 2: //撤户
                                                tagTPE_QueryFlowRes_Open FlowRes_Close = new tagTPE_QueryFlowRes_Open();
                                                FlowRes_Close = (tagTPE_QueryFlowRes_Open)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Open));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 2;
                                                Tpe_CRO.CenterNo = FlowRes_Close.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Close.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Close.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Close.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_Close.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Close.CardNo;
                                                Tpe_CRO.Balance = FlowRes_Close.Balance;
                                                Tpe_CRO.Condition = FlowRes_Close.Condition;
                                                Tpe_CRO.TransferLimit = FlowRes_Close.TransferLimit;
                                                Tpe_CRO.TransferMoney = FlowRes_Close.TransferMoney;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Close);
                                                break;
                                            case 3: //建立对应关系
                                                tagTPE_QueryFlowRes_BuildRelation FlowRes_Create = new tagTPE_QueryFlowRes_BuildRelation();
                                                FlowRes_Create = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 3;
                                                Tpe_CRO.CenterNo = FlowRes_Create.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Create.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Create.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Create.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_Create.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Create.CardNo;
                                                Tpe_CRO.JoinCardHolder = FlowRes_Create.JoinCardHolder;
                                                Tpe_CRO.JoinNode = FlowRes_Create.JoinNode;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Create);
                                                break;
                                            case 4: //撤消对应
                                                tagTPE_QueryFlowRes_BuildRelation FlowRes_Drop = new tagTPE_QueryFlowRes_BuildRelation();
                                                FlowRes_Drop = (tagTPE_QueryFlowRes_BuildRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_BuildRelation));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 4;
                                                Tpe_CRO.CenterNo = FlowRes_Drop.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Drop.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Drop.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Drop.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_Drop.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Drop.CardNo;
                                                Tpe_CRO.JoinCardHolder = FlowRes_Drop.JoinCardHolder;
                                                Tpe_CRO.JoinNode = FlowRes_Drop.JoinNode;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Drop);
                                                break;
                                            case 5: //更改帐户信息
                                                tagTPE_QueryFlowRes_UpdateAccount FlowRes_Update = new tagTPE_QueryFlowRes_UpdateAccount();
                                                FlowRes_Update = (tagTPE_QueryFlowRes_UpdateAccount)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateAccount));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 5;
                                                Tpe_CRO.CenterNo = FlowRes_Update.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Update.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Update.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Update.OccurTime;
                                                string dt = string.Empty;
                                                string hh = string.Empty;
                                                dt = System.Text.Encoding.Default.GetString(Tpe_CRO.OccurTime);
                                                hh = dt.Substring(8, 2);
                                                Tpe_CRO.AccountNo = FlowRes_Update.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Update.CardNo;
                                                Tpe_CRO.TransferLimit = FlowRes_Update.TransferLimit;
                                                Tpe_CRO.TransferMoney = FlowRes_Update.TransferMoney;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                //if (int.Parse(hh) > 1) { listCRO.Add(cTpe_Cro); }
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Update);
                                                //tagTPE_GetAccountReq ReqA = new tagTPE_GetAccountReq();
                                                //tagTPE_GetAccountRes ResA = new tagTPE_GetAccountRes();
                                                //ReqA.AccountNo = FlowRes_Update.AccountNo;
                                                //ReqA.resflagAccountNo = 1;     //帐号
                                                //ReqA.resflagCardNo = 1;        //卡号
                                                //ReqA.resflagCondition = 1;     //状态
                                                //ReqA.resflagBalance = 1;       //余额
                                                //ReqA.resflagName = 1;          //姓名
                                                //ReqA.resflagPersonID = 1;      //身份证号
                                                //ReqA.resflagPassword = 1;      //密码 
                                                //ReqA.resflagBirthday = 1;      //出生日期
                                                //ReqA.resflagDepart = 1;        //部门
                                                //ReqA.resflagIdenti = 1;        //身份
                                                //ReqA.resflagNation = 1;        //民族国籍
                                                //ReqA.resflagTel = 1;           //电话
                                                //int nRetA = TPE_Class.TPE_GetAccount(1, ref ReqA, out ResA, 1);
                                                break;
                                            case 6: //更改对应关系
                                                tagTPE_QueryFlowRes_UpdateRelation FlowRes_UpdateRelation = new tagTPE_QueryFlowRes_UpdateRelation();
                                                FlowRes_UpdateRelation = (tagTPE_QueryFlowRes_UpdateRelation)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_UpdateRelation));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 6;
                                                Tpe_CRO.CenterNo = FlowRes_UpdateRelation.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_UpdateRelation.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_UpdateRelation.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_UpdateRelation.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_UpdateRelation.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_UpdateRelation.CardNo;
                                                Tpe_CRO.JoinCardHolder = FlowRes_UpdateRelation.JoinCardHolder;
                                                Tpe_CRO.JoinNode = FlowRes_UpdateRelation.JoinNode;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_UpdateRelation);
                                                break;
                                            case 7: //余额变更, 不区分具体来源
                                            case 8: //余额变更, 由相关操作引发
                                            case 9: //余额变更, 存取款引发
                                                tagTPE_QueryFlowRes_Cost FlowRes_Cost9 = new tagTPE_QueryFlowRes_Cost();
                                                FlowRes_Cost9 = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Cost));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 9;
                                                Tpe_CRO.CenterNo = FlowRes_Cost9.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Cost9.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Cost9.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Cost9.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_Cost9.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Cost9.CardNo;
                                                Tpe_CRO.Balance = FlowRes_Cost9.Balance;
                                                Tpe_CRO.JoinNode = FlowRes_Cost9.JoinNode;
                                                Tpe_CRO.JoinCardHolder = FlowRes_Cost9.JoinCardHolder;
                                                Tpe_CRO.TransMoney = FlowRes_Cost9.TransMoney;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Cost9);
                                                Offset += (int)FlowRes_Cost9.ExtendLen;
                                                break;
                                            case 10: //余额变更, 由补助扣款引发
                                            case 11: //余额变更, 卡片交易引发
                                            case 12: //余额变更, 银行转帐引发 
                                            case 13: //余额变更, 通用缴费 
                                            case 14: //余额变更, 押金 
                                            case 15: //余额变更, 管理费 
                                                tagTPE_QueryFlowRes_Cost FlowRes_Cost15 = new tagTPE_QueryFlowRes_Cost();
                                                FlowRes_Cost15 = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Cost));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 15;
                                                Tpe_CRO.CenterNo = FlowRes_Cost15.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Cost15.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Cost15.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Cost15.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_Cost15.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Cost15.CardNo;
                                                Tpe_CRO.Balance = FlowRes_Cost15.Balance;
                                                Tpe_CRO.JoinNode = FlowRes_Cost15.JoinNode;
                                                Tpe_CRO.JoinCardHolder = FlowRes_Cost15.JoinCardHolder;
                                                Tpe_CRO.TransMoney = FlowRes_Cost15.TransMoney;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Cost15);
                                                Offset += (int)FlowRes_Cost15.ExtendLen;
                                                break;
                                            case 16: //余额变更, 手续费 
                                            case 17: //余额变更, 工本费 
                                            case 18: //余额变更,内部转出
                                            case 19: //余额变更,内部转入
                                                tagTPE_QueryFlowRes_Cost FlowRes_Cost = new tagTPE_QueryFlowRes_Cost();
                                                FlowRes_Cost = (tagTPE_QueryFlowRes_Cost)Marshal.PtrToStructure(new IntPtr(buffer.ToInt32() + Offset), typeof(tagTPE_QueryFlowRes_Cost));
                                                Tpe_CRO = new tagTPE_CReturnObj();
                                                Tpe_CRO.TransType = 7;
                                                Tpe_CRO.CenterNo = FlowRes_Cost.CenterNo;
                                                Tpe_CRO.OccurNode = FlowRes_Cost.OccurNode;
                                                Tpe_CRO.OccurIdNo = FlowRes_Cost.OccurIdNo;
                                                Tpe_CRO.OccurTime = FlowRes_Cost.OccurTime;
                                                Tpe_CRO.AccountNo = FlowRes_Cost.AccountNo;
                                                Tpe_CRO.CardNo = FlowRes_Cost.CardNo;
                                                Tpe_CRO.Balance = FlowRes_Cost.Balance;
                                                Tpe_CRO.JoinNode = FlowRes_Cost.JoinNode;
                                                Tpe_CRO.JoinCardHolder = FlowRes_Cost.JoinCardHolder;
                                                Tpe_CRO.TransMoney = FlowRes_Cost.TransMoney;
                                                cTpe_Cro = new TPE_CReturnObj(Tpe_CRO);
                                                listCRO.Add(cTpe_Cro);
                                                Offset += Marshal.SizeOf(FlowRes_Cost);
                                                Offset += (int)FlowRes_Cost.ExtendLen;
                                                break;
                                        }
                                        Offset += 4;
                                    }
                                    //TPE_Class.TPE_Free(ref Res.pRes);
                                    retRes.Result = "ok";
                                    retRes.Msg = "成功";
                                    retRes.ListDate = listCRO;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg += "服务器异常.按中心记帐号查询流水异常：" + e.Message;
                CPublic.WriteLog("按中心记帐号查询流水异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("按中心记帐号查询流水异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 枚举部门
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_ConfigEnumDepartment(string NodeNo, string MAC)
        {
            CReturnConfigDeptRec retRes = new CReturnConfigDeptRec();
            List<TPE_ConfigDeptRec> listRes = new List<TPE_ConfigDeptRec>();
            string json = "";
            try
            {
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (CheckNode(NodeNo, "", MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, "", MAC)];
                }
                else
                {
                    tagTPE_ConfigEnumDeptReq Req = new tagTPE_ConfigEnumDeptReq();
                    tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                    Req.RangeDept = new ulong[2];
                    Req.RangeDept[0] = 0;
                    Req.RangeDept[1] = 0x7fffffffffffffff;
                    Req.Depth = 8;

                    int nRet = TPE_Class.TPE_ConfigEnumDept(1, ref Req, out Res, 1);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "nRet=" + nRet.ToString();
                    }
                    else
                    {
                        if (Res.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "ResRecCount=" + Res.ResRecCount.ToString();
                        }
                        else
                        {
                            tagTPE_ConfigDeptRec DeptRec = new tagTPE_ConfigDeptRec();
                            TPE_ConfigDeptRec Ctpe_Cdr;
                            IntPtr buffer;
                            for (int i = 0; i < Res.ResRecCount; i++)
                            {
                                buffer = (IntPtr)((Byte*)(Res.pRes) + i * System.Runtime.InteropServices.Marshal.SizeOf(DeptRec));
                                DeptRec = (tagTPE_ConfigDeptRec)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer, typeof(tagTPE_ConfigDeptRec));
                                Ctpe_Cdr = new TPE_ConfigDeptRec(DeptRec);
                                listRes.Add(Ctpe_Cdr);
                            }
                            Res.pRes = null;
                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.ListDate = listRes;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("枚举部门异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("枚举部门异常 ToJson:" + ex.Message);
            }
            return json;
        }


        /// <summary>
        /// 下载白名单
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_ConfigDownloadWhiteList(string NodeNo, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            List<TPE_GetAccountRes> listRes = new List<TPE_GetAccountRes>();
            string json = "";
            try
            {
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (CheckNode(NodeNo, "", MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, "", MAC)];
                }
                else
                {
                    TPE_Class.TPE_DownloadAllWL();

                    for (int loop = 0x0001; loop <= 0xFFFF; loop++)
                    {
                        tagWhiteListRec Rec = new tagWhiteListRec();
                        TPE_GetAccountRes tpe_GetAccRes;
                        Rec.AccountNo = 100000 + loop;
                        Rec.CardNo = 0;
                        int ret = TPE_Class.TPE_GetWL(out Rec);
                        if (Rec.CardNo > 0)
                        {
                            tagTPE_GetAccountRes item = new tagTPE_GetAccountRes();
                            item.AccountNo = Rec.AccountNo;
                            item.Condition = (uint) Rec.Condition;
                            item.Balance = Rec.Balance;
                            item.CardNo = Rec.CardNo;
                            item.Depart = Rec.Depart;
                            item.Identi = Rec.Identi;
                            item.Birthday = new byte[1];
                            item.ExpireDate = new byte[1];
                            item.CreateTime = new byte[1];
                            item.UpdateTime = new byte[1];
                            item.Name = new byte[]{ Rec.Sign };
                            tpe_GetAccRes = new TPE_GetAccountRes(item);
                            listRes.Add(tpe_GetAccRes);
                        }
                    }
                    retRes.Result = "ok";
                    retRes.Msg = "成功";
                    retRes.ListDate = listRes;
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("白名单异常：" + e.Message + e.ToString());
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("白名单异常 ToJson:" + ex.Message + ex.ToString());
            }
            return json;
        }

        /// <summary>
        /// 枚举身份
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_ConfigEnumIdenti(string NodeNo, string MAC)
        {
            CReturnConfigIdentiRec retRes = new CReturnConfigIdentiRec();
            List<TPE_ConfigIdentiRec> listRes = new List<TPE_ConfigIdentiRec>();
            string json = "";
            try
            {
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (CheckNode(NodeNo, "", MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, "", MAC)];
                }
                else
                {
                    tagTPE_ConfigEnumIdentiReq Req = new tagTPE_ConfigEnumIdentiReq();
                    tagTPE_QueryResControl Res = new tagTPE_QueryResControl();
                    Req.RangeIdenti = new Int16[2];
                    Req.RangeIdenti[0] = 0;
                    Req.RangeIdenti[1] = 0x7fff;
                    int nRet = TPE_Class.TPE_ConfigEnumIdenti(1, ref Req, out Res, 1);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "nRet=" + nRet.ToString();
                    }
                    else
                    {
                        if (Res.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "ResRecCount=" + Res.ResRecCount.ToString();
                        }
                        else
                        {
                            tagTPE_ConfigIdentiRec IdentiRec = new tagTPE_ConfigIdentiRec();
                            TPE_ConfigIdentiRec cTpe_Cir;
                            IntPtr buffer;
                            for (int i = 0; i < Res.ResRecCount; i++)
                            {
                                buffer = (IntPtr)((Byte*)(Res.pRes) + i * System.Runtime.InteropServices.Marshal.SizeOf(IdentiRec));
                                IdentiRec = (tagTPE_ConfigIdentiRec)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer, typeof(tagTPE_ConfigIdentiRec));
                                cTpe_Cir = new TPE_ConfigIdentiRec(IdentiRec);
                                listRes.Add(cTpe_Cir);
                            }
                            Res.pRes = null;
                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.ListDate = listRes;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("枚举身份异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("枚举身份异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 下载白名单
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        unsafe public string TPE_ConfigThirdChecker(string NodeNo, string MAC)
        {
            CReturnGetAccountRes retRes = new CReturnGetAccountRes();
            List<TPE_GetAccountRes> listRes = new List<TPE_GetAccountRes>();
            string json = "";
            try
            {
                int nodeNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (CheckNode(NodeNo, "", MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, "", MAC)];
                }
                else
                {
                    TPE_Class.TPE_DownloadAllWL();

                    for (int loop = 0x0001; loop <= 0xFFFF; loop++)
                    {
                        tagWhiteListRec Rec = new tagWhiteListRec();
                        TPE_GetAccountRes tpe_GetAccRes;
                        Rec.AccountNo = 100000 + loop;
                        Rec.CardNo = 0;
                        int ret = TPE_Class.TPE_GetWL(out Rec);
                        if (Rec.CardNo > 0)
                        {
                            tagTPE_GetAccountRes item = new tagTPE_GetAccountRes();
                            item.AccountNo = Rec.AccountNo;
                            item.Condition = (uint)Rec.Condition;
                            item.Balance = Rec.Balance;
                            item.CardNo = Rec.CardNo;
                            item.Depart = Rec.Depart;
                            item.Identi = Rec.Identi;
                            item.Birthday = new byte[1];
                            item.ExpireDate = new byte[1];
                            item.CreateTime = new byte[1];
                            item.UpdateTime = new byte[1];
                            item.Name = new byte[] { Rec.Sign };
                            tpe_GetAccRes = new TPE_GetAccountRes(item);
                            listRes.Add(tpe_GetAccRes);
                        }
                    }
                    retRes.Result = "ok";
                    retRes.Msg = "成功";
                    retRes.ListDate = listRes;
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("白名单异常：" + e.Message + e.ToString());
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("白名单异常 ToJson:" + ex.Message + ex.ToString());
            }
            return json;
        }


        /// <summary>
        /// 帐户自定义字段
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="AccountNo">帐号</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        public string TPE_GetAccountEx(string NodeNo, string AccountNo, string MAC)
        {
            CReturnGetAccountExRes retRes = new CReturnGetAccountExRes();
            string json = "";
            try
            {
                int nodeNo; int accNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(AccountNo) || !int.TryParse(AccountNo, out accNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo(类型Int)]";
                }
                else if (CheckNode(NodeNo, AccountNo, MAC) != 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, "", MAC)];
                }
                else
                {
                    tagTPE_GetAccountExRes Res = new tagTPE_GetAccountExRes();

                    int nRet = TPE_Class.TPE_GetAccountEx(1, accNo, out Res);
                    if (nRet != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "nRet=" + nRet.ToString();
                    }
                    else
                    {
                        if (Res.RetValue == -1 || Res.RetValue == -2)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "RetValue=" + Res.RetValue.ToString();
                        }
                        else
                        {
                            TPE_GetAccountExRes Gaer = new TPE_GetAccountExRes(Res);
                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.Data = Gaer;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("帐户自定义字段 异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("帐户自定义字段 异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 修改帐户信息 电话 邮件 备注 
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="AccountNo">帐号(卡号传入一项即可)</param>
        /// <param name="CardNo">卡号(帐号传入一项即可)</param>
        /// <param name="Tel">电话</param>
        /// <param name="Email">邮件</param>
        /// <param name="Comment">备注</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        public string TPE_FlowUpdateAccount(string NodeNo, string AccountNo, string CardNo, string Tel, string Email, string Comment, string MAC)
        {
            CReturnFlowUpdateAccountRes retRes = new CReturnFlowUpdateAccountRes();
            string json = "";
            try
            {
                int nodeNo; int accNo; int cardNo;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(AccountNo) && string.IsNullOrEmpty(CardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo/CardNo(至少传入一项)]";
                }
                else if (!string.IsNullOrEmpty(AccountNo) && !int.TryParse(AccountNo, out accNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo(类型Int)]";
                }
                else if (!string.IsNullOrEmpty(CardNo) && !int.TryParse(CardNo, out cardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[CardNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(Tel) && string.IsNullOrEmpty(Email) && string.IsNullOrEmpty(Comment))
                {
                    retRes.Result = "error";
                    retRes.Msg = "参数[Tel][Email][Remark]，至少传入一项";
                }
                else
                {
                    string param = "";
                    if (!string.IsNullOrEmpty(AccountNo) && string.IsNullOrEmpty(CardNo))
                    {
                        param = AccountNo;
                    }
                    else if (string.IsNullOrEmpty(AccountNo) && !string.IsNullOrEmpty(CardNo))
                    {
                        param = CardNo;
                    }
                    else if (!string.IsNullOrEmpty(AccountNo) && !string.IsNullOrEmpty(CardNo))
                    {
                        param = AccountNo + "$" + CardNo;
                    }
                    if (!string.IsNullOrEmpty(Tel))
                    {
                        param = param + "$" + Tel;
                    }
                    if (!string.IsNullOrEmpty(Email))
                    {
                        param = param + "$" + Email;
                    }
                    if (!string.IsNullOrEmpty(Comment))
                    {
                        param = param + "$" + Comment;
                    }
                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, "", MAC)];
                    }
                    else
                    {
                        tagTPE_OnLineGetMaxSnRes SnRes = new tagTPE_OnLineGetMaxSnRes();
                        TPE_Class.TPE_OnLineGetMaxSn(1, out SnRes, 1);
                        tagTPE_FlowUpdateAccountReq ReqU = new tagTPE_FlowUpdateAccountReq();
                        tagTPE_FlowUpdateAccountRes ResU = new tagTPE_FlowUpdateAccountRes();
                        ReqU.TranOper = 0;
                        ReqU.reqflagTel = 1;
                        ReqU.reqflagEmail = 1;
                        ReqU.reqflagComment = 1;
                        ReqU.OccurIdNo = (UInt32)(SnRes.MaxSn + 1);
                        ReqU.OccurTime = new byte[14];
                        byte[] tmp = System.Text.Encoding.ASCII.GetBytes(DateTime.Now.ToString("yyyyMMddHHmmss"));
                        Array.Copy(tmp, ReqU.OccurTime, tmp.Length);
                        if (!string.IsNullOrEmpty(AccountNo))
                        {
                            ReqU.ReqAccountNo = System.Convert.ToUInt32(AccountNo);
                        }
                        if (!string.IsNullOrEmpty(CardNo))
                        {
                            ReqU.ReqCardNo = System.Convert.ToInt32(CardNo);
                        }
                        ReqU.Password = new byte[8];
                        tmp = System.Text.Encoding.ASCII.GetBytes(Tel);
                        ReqU.Tel = new byte[48];
                        Array.Copy(tmp, ReqU.Tel, tmp.Length > 48 ? 48 : tmp.Length);
                        tmp = System.Text.Encoding.ASCII.GetBytes(Email);
                        ReqU.Email = new byte[48];
                        Array.Copy(tmp, ReqU.Email, tmp.Length > 48 ? 48 : tmp.Length);
                        tmp = System.Text.Encoding.ASCII.GetBytes(Comment);
                        ReqU.Comment = new byte[120];
                        Array.Copy(tmp, ReqU.Comment, tmp.Length > 120 ? 120 : tmp.Length);

                        int nRet = TPE_Class.TPE_FlowUpdateAccount(1, ref ReqU, out ResU, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "nRet=" + nRet.ToString();
                        }
                        else
                        {
                            if (ResU.RecordError != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "RecordError=" + ResU.RecordError.ToString();
                            }
                            else
                            {
                                TPE_FlowUpdateAccountRes Fuar = new TPE_FlowUpdateAccountRes(ResU);
                                Fuar.CenterNo = QueryOccurByCenterUINT(NodeNo, Fuar.OccurIdNo);
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.Data = Fuar;
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("更新账户 异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("更新账户 异常 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 补助/扣款
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="AccountNo">帐号(卡号传入一项即可)</param>
        /// <param name="CardNo">卡号(帐号传入一项即可)</param>
        /// <param name="TransMoney">充值金额 单位分 补助>0 扣款<0</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        [WebMethod]
        public string TPE_FlowCost(string NodeNo, string AccountNo, string CardNo, string TransMoney, string MAC)
        {
            CReturnFlowCostRes retRes = new CReturnFlowCostRes();
            string json = "";
            try
            {
                int nodeNo; int accNo; int transMoney;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(AccountNo) && string.IsNullOrEmpty(CardNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo/CardNo(至少传入一项)] // 不再允许";
                }
                else if (AccountNo.Length <= 0 && CardNo.Length <= 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo/CardNo(必须传入)] [[[" + AccountNo + "---" + CardNo + "]]]";
                }
                else if (string.IsNullOrEmpty(AccountNo) || !int.TryParse(AccountNo, out accNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[AccountNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(TransMoney) || !int.TryParse(TransMoney, out transMoney))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[TransMoney(类型Int,单位:分)]";
                }
                else if (transMoney == 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[TransMoney(金额不能为0,大于0补助,小于0扣款)]";
                }
                else
                {

                    string param = "";
                    if (!string.IsNullOrEmpty(AccountNo) && !string.IsNullOrEmpty(CardNo))
                    {
                        param = AccountNo + "$" + CardNo;
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(AccountNo))
                        {
                            param = AccountNo;
                        }
                        else
                        {
                            param = CardNo;
                        }
                    }
                    param = param + "$" + transMoney;
                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                    }
                    else
                    {
                        tagTPE_OnLineGetMaxSnRes SnRes = new tagTPE_OnLineGetMaxSnRes();
                        TPE_Class.TPE_OnLineGetMaxSn(1, out SnRes, 1);
                        tagTPE_FlowCostReq ReqL = new tagTPE_FlowCostReq();
                        tagTPE_FlowCostRes ResF = new tagTPE_FlowCostRes();
                        ReqL.OccurIdNo = SnRes.MaxSn + 1;
                        byte[] occurtime = Encoding.GetEncoding("gb2312").GetBytes(DateTime.Now.ToString("yyyyMMddHHmmss"));
                        ReqL.OccurTime = new byte[14];
                        Array.Copy(occurtime, ReqL.OccurTime, 14);
                        if (!string.IsNullOrEmpty(AccountNo))
                        {
                            ReqL.AccountNo = System.Convert.ToInt32(AccountNo);
                        }
                        if (!string.IsNullOrEmpty(CardNo))
                        {
                            ReqL.CardNo = System.Convert.ToInt32(CardNo);
                        }
                        ReqL.CostType = 9;
                        ReqL.TransMoney = transMoney;
                        int nRet = TPE_Class.TPE_FlowCost(1, ref ReqL, 1, out ResF, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "nRet=" + nRet.ToString();
                        }
                        else
                        {
                            TPE_FlowCostRes Fr = new TPE_FlowCostRes(ResF);
                            Fr.CenterNo = QueryOccurByCenter(NodeNo, Fr.OccurIdNo);
                            retRes.Result = "ok";
                            retRes.Msg = "成功";
                            retRes.Data = Fr;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常." + e.Message;
                CPublic.WriteLog("充值异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常." + ex.Message;
                CPublic.WriteLog("充值 ToJson:" + ex.Message);
            }
            return json;
        }

        [WebMethod]
        public string TPE_FlowCostByCertCode(string NodeNo, string CertCode, string TransMoney, string MAC)
        {
            CReturnFlowCostRes retRes = new CReturnFlowCostRes();
            string json = "";
            try
            {
                int nodeNo; int transMoney;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(CertCode))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[CertCode]";
                }
                else if (string.IsNullOrEmpty(TransMoney) || !int.TryParse(TransMoney, out transMoney))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[TransMoney(类型Int,单位:分)]";
                }
                else if (transMoney == 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[TransMoney(金额不能为0,大于0补助,小于0扣款)]";
                }
                else
                {

                    string param = CertCode + "$" + transMoney;
                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                    }
                    else
                    {
                        tagTPE_QueryGeneralAccountReq Req = new tagTPE_QueryGeneralAccountReq();
                        tagTPE_QueryResControl ResControl = new tagTPE_QueryResControl();

                        Req.SQL = "where CertCode = '" + CertCode.Trim() + "'";
                        Req.resflagName = 1;
                        Req.resflagCondition = 1;
                        Req.resflagBalance = 1;
                        Req.resflagDepart = 1;

                        int nRet = TPE_Class.TPE_QueryGeneralAccount(1, ref Req, out ResControl, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "工号调账失败！ nRet=" + nRet.ToString();
                        }
                        else if (ResControl.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "工号不存在！";
                        }
                        else if (ResControl.ResRecCount > 1)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "此工号对应帐户不唯一！";
                        }
                        else
                        {
                            tagTPE_GetAccountRes AccRes = new tagTPE_GetAccountRes();
                            unsafe
                            {
                                IntPtr buffer = (IntPtr)((Byte*)(ResControl.pRes));
                                AccRes = (tagTPE_GetAccountRes)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer, typeof(tagTPE_GetAccountRes));
                                ResControl.pRes = null;
                            }
                            tagTPE_OnLineGetMaxSnRes SnRes = new tagTPE_OnLineGetMaxSnRes();
                            TPE_Class.TPE_OnLineGetMaxSn(1, out SnRes, 1);
                            tagTPE_FlowCostReq ReqL = new tagTPE_FlowCostReq();
                            tagTPE_FlowCostRes ResF = new tagTPE_FlowCostRes();
                            ReqL.OccurIdNo = SnRes.MaxSn + 1;
                            byte[] occurtime = Encoding.GetEncoding("gb2312").GetBytes(DateTime.Now.ToString("yyyyMMddHHmmss"));
                            ReqL.OccurTime = new byte[14];
                            Array.Copy(occurtime, ReqL.OccurTime, 14);
                            ReqL.AccountNo = AccRes.AccountNo;
                            ReqL.CostType = 9;
                            ReqL.TransMoney = transMoney;

                            nRet = TPE_Class.TPE_FlowCost(1, ref ReqL, 1, out ResF, 1);
                            if (nRet != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "nRet=" + nRet.ToString();
                            }
                            else
                            {
                                TPE_FlowCostRes Fr = new TPE_FlowCostRes(ResF);
                                Fr.CenterNo = QueryOccurByCenter(NodeNo, Fr.OccurIdNo);
                                int IDNO = ResF.OccurIdNo;
                                int CTNO = ResF.CenterNo;
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.Data = Fr;
                            }
                        }

                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("充值异常：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("充值 ToJson:" + ex.Message);
            }
            return json;
        }

        [WebMethod]
        public string TPE_FlowCostByIDNO(string NodeNo, string IDNO, string TransMoney, string MAC)
        {
            CReturnFlowCostRes retRes = new CReturnFlowCostRes();
            string json = "";
            try
            {
                int nodeNo; int transMoney;
                if (string.IsNullOrEmpty(NodeNo) || !int.TryParse(NodeNo, out nodeNo))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[NodeNo(类型Int)]";
                }
                else if (string.IsNullOrEmpty(MAC))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[MAC]";
                }
                else if (string.IsNullOrEmpty(IDNO))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[IDNO]";
                }
                else if (string.IsNullOrEmpty(TransMoney) || !int.TryParse(TransMoney, out transMoney))
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[TransMoney(类型Int,单位:分)]";
                }
                else if (transMoney == 0)
                {
                    retRes.Result = "error";
                    retRes.Msg = "请传入有效参数[TransMoney(金额不能为0,大于0补助,小于0扣款)]";
                }
                else
                {

                    string param = IDNO + "$" + transMoney;
                    if (CheckNode(NodeNo, param, MAC) != 0)
                    {
                        retRes.Result = "error";
                        retRes.Msg = "节点校验失败！" + NodeCheckInfo[CheckNode(NodeNo, param, MAC)];
                    }
                    else
                    {
                        tagTPE_QueryGeneralAccountReq Req = new tagTPE_QueryGeneralAccountReq();
                        tagTPE_QueryResControl ResControl = new tagTPE_QueryResControl();

                        Req.SQL = "where PersonID = '" + IDNO.Trim() + "'";
                        Req.resflagName = 1;
                        Req.resflagCondition = 1;
                        Req.resflagBalance = 1;
                        Req.resflagDepart = 1;

                        int nRet = TPE_Class.TPE_QueryGeneralAccount(1, ref Req, out ResControl, 1);
                        if (nRet != 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "身份证调账失败！ nRet=" + nRet.ToString();
                        }
                        else if (ResControl.ResRecCount == 0)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "身份证不存在！";
                        }
                        else if (ResControl.ResRecCount > 1)
                        {
                            retRes.Result = "error";
                            retRes.Msg = "此身份证对应帐户不唯一！";
                        }
                        else
                        {
                            tagTPE_GetAccountRes AccRes = new tagTPE_GetAccountRes();
                            unsafe
                            {
                                IntPtr buffer = (IntPtr)((Byte*)(ResControl.pRes));
                                AccRes = (tagTPE_GetAccountRes)System.Runtime.InteropServices.Marshal.PtrToStructure(buffer, typeof(tagTPE_GetAccountRes));
                                ResControl.pRes = null;
                            }
                            tagTPE_OnLineGetMaxSnRes SnRes = new tagTPE_OnLineGetMaxSnRes();
                            TPE_Class.TPE_OnLineGetMaxSn(1, out SnRes, 1);
                            tagTPE_FlowCostReq ReqL = new tagTPE_FlowCostReq();
                            tagTPE_FlowCostRes ResF = new tagTPE_FlowCostRes();
                            ReqL.OccurIdNo = SnRes.MaxSn + 1;
                            byte[] occurtime = Encoding.GetEncoding("gb2312").GetBytes(DateTime.Now.ToString("yyyyMMddHHmmss"));
                            ReqL.OccurTime = new byte[14];
                            Array.Copy(occurtime, ReqL.OccurTime, 14);
                            ReqL.AccountNo = AccRes.AccountNo;
                            ReqL.CostType = 9;
                            ReqL.TransMoney = transMoney;

                            nRet = TPE_Class.TPE_FlowCost(1, ref ReqL, 1, out ResF, 1);
                            if (nRet != 0)
                            {
                                retRes.Result = "error";
                                retRes.Msg = "nRet=" + nRet.ToString();
                            }
                            else
                            {
                                TPE_FlowCostRes Fr = new TPE_FlowCostRes(ResF);
                                Fr.CenterNo = QueryOccurByCenter(NodeNo, Fr.OccurIdNo);
                                retRes.Result = "ok";
                                retRes.Msg = "成功";
                                retRes.Data = Fr;
                            }
                        }

                    }
                }
            }
            catch (Exception e)
            {
                retRes.Result = "error";
                retRes.Msg = "服务器异常.";
                CPublic.WriteLog("充值异常1：" + e.Message);
            }
            try
            {
                JavaScriptSerializer jss = new JavaScriptSerializer();
                json = jss.Serialize(retRes);
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("充值1 ToJson:" + ex.Message);
            }
            return json;
        }

        /// <summary>
        /// 验证节点是否正确
        /// </summary>
        /// <param name="NodeNo">节点号</param>
        /// <param name="param">参数(参数间加$符号)</param>
        /// <param name="MAC">MAC</param>
        /// <returns></returns>
        public int CheckNode(string NodeNo, string param, string MAC)
        {
            try
            {
                if (NodeNo != CPublic.LocalNode)
                {
                    CPublic.WriteLog("验证节点失败 NodeNo=" + NodeNo + ";LocalNode=" + CPublic.LocalNode);
                    return 1;
                }
                //（shareKey+$+参数(参数间+$)）
                string shareKey = "Synj0nes";
                if (!string.IsNullOrEmpty(param))
                {
                    shareKey = shareKey + "$" + param;
                }
                string pass = "$senOjnyS";
                shareKey += pass;
                if (shareKey != MAC)
                {
                    CPublic.WriteLog("验证参数失败 shareKey=" + shareKey + ";mac=" + MAC + ";param=" + param);
                    return 2;
                }
                else
                {
                    return 0;
                }
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("查询节点失败,异常:" + ex.Message);
                return 3;
            }
        }
        public string CheckNodeDetail(string NodeNo, string param, string MAC)
        {
            try
            {
                if (NodeNo != CPublic.LocalNode)
                {
                    return "验证节点失败 NodeNo=" + NodeNo + ";LocalNode=" + CPublic.LocalNode;
                }
                //（shareKey+$+参数(参数间+$)）
                string shareKey = "Synj0nes";
                if (!string.IsNullOrEmpty(param))
                {
                    shareKey = shareKey + "$" + param;
                }
                string pass = "$senOjnyS";
                shareKey += pass;
                if (shareKey != MAC)
                {
                    return "验证参数失败 shareKey=" + shareKey + ";mac=" + MAC + ";param=" + param;
                }
                else
                {
                    return "OK";
                }
            }
            catch (Exception ex)
            {
                CPublic.WriteLog("查询节点失败,异常:" + ex.Message);
                return "查询节点失败,异常:" + ex.Message;
            }
        }
    }
}
