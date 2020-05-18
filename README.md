# WebService
用于新中新©金龙一卡通®系统第三方接口

全新 Token 认证接口使用帮助：
第一步、获取 Token
访问接口 TPE_ApplyToken，通过 POST 发送
	Username: 0
	Password: 00000000
	MAC: Synj0nes$0$00000000$senOjnyS
返回 Token 的 Base64 编码结果，请检查 Token 解码后长度为 32 位。
注：可用用户名为 0 与 1，密码为 00000000 与 11111111

第二步、访问接口
访问任意接口，通过 POST 发送
	NodeNo: 本地节点（如 10）
	Username: 2
	其他数据: xxx
	SHA: SHA1(Username + $ + xxx + $ Token)
Token 长度为 32 位，将所有 POST 数据的文本使用 $ 合并后计算 SHA1。
伪代码：
"$".join({
    "2",
    "xxx",
    "20201231235959"
});

第三步、返回数据
请注意，单个 Token 可使用三十次，建议每队列操作不超过十次。
对于并发的情况，建议保持两个全局 Token 循环使用，该问题正在优化。

接口表：
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
