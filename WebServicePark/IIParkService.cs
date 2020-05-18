namespace WebServicePark {
    public interface IIParkService {
        int CheckNode (string NodeNo, string param, string SHA);
        int CheckNodeUsingToken (string NodeNo, string username, string param, string SHA, string DoingLog);
        string getTokenStatusInfo (int index);
        bool isAllow (string FuncName);
        int isOrderIDExist (string OrderID, string OrderStatus);
        string TPE_ApplyToken (string NodeNo, string Username, string Password, string MAC);
        string TPE_AuthUpdate (string Submit);
        string TPE_ChangeAccountPassword (string NodeNo, string Username, string AccountNo, string CardNo, string OldPassWord, string NewPassWord, string SHA);
        string TPE_CheckPassword (string NodeNo, string Username, string AccountNo, string CardNo, string PassWord, string SHA);
        string TPE_ConditionParse (string Condition);
        string TPE_ConfigDownloadWhiteList (string NodeNo, string Username, string SHA);
        string TPE_ConfigEnumDepartment (string NodeNo, string Username, string SHA);
        string TPE_ConfigEnumIdenti (string NodeNo, string Username, string SHA);
        string TPE_FlowCost (string NodeNo, string Username, string AccountNo, string CardNo, string OrderID, string TransMoney, string SHA);
        string TPE_FlowCostMinus (string NodeNo, string Username, string AccountNo, string CardNo, string OrderID, string TransMoney, string SHA);
        string TPE_FlowCostPlus (string NodeNo, string Username, string AccountNo, string CardNo, string OrderID, string TransMoney, string SHA);
        string TPE_FlowUpdateAccount (string NodeNo, string Username, string AccountNo, string CardNo, string Tel, string Email, string Comment, string SHA);
        string TPE_GetAccount (string NodeNo, string Username, string CardNo, string SHA);
        string TPE_GetAccountByCertNo (string NodeNo, string Username, string CertNo, string SHA);
        string TPE_GetAccountByIDNo (string NodeNo, string Username, string IDNO, string SHA);
        string TPE_GetAccountByNo (string NodeNo, string Username, string AccountNo, string SHA);
        string TPE_GetAccountEx (string NodeNo, string Username, string AccountNo, string SHA);
        string TPE_LostAccount (string NodeNo, string Username, string AccountNo, string PassWord, string Operation, string SHA);
        string TPE_QueryFlowByAccount (string NodeNo, string Username, string AccountNo, string BeginTime, string EndTime, string SHA);
        string TPE_QueryFlowByCenter (string NodeNo, string Username, string FromCentralNo, string ToCentralNo, string SHA);
        string TPE_QueryFlowByCertNo (string NodeNo, string Username, string CertCode, string BeginTime, string EndTime, string SHA);
        string TPE_QueryFlowByOccur (string NodeNo, string Username, string OccurNodeNo, string FromOccurNo, string ToOccurNo, string SHA);
        string TPE_QueryFlowByOrderID (string NodeNo, string Username, string OrderID, string OrderStatus, string SHA);
        string TPE_QueryStdAccount (string NodeNo, string Username, string BeginNo, string EndNo, string SHA);
        string TPE_RefundByCenterID (string NodeNo, string Username, string AccountNo, string CenterID, string OrderID, string TransMoney, string SHA);
    }
}