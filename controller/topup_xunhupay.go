package controller

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/shopspring/decimal"
)

// ===== 虎皮椒(XunHuPay) 支付适配器 =====
// 替代标准易支付协议，直接对接虎皮椒 JSON API

// XunHuPayResponse 虎皮椒支付响应
type XunHuPayResponse struct {
	OpenID  string `json:"openid"`
	URL     string `json:"url"`
	URLQr   string `json:"url_qrcode"`
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
	Hash    string `json:"hash"`
}

// generateXunHuHash 生成虎皮椒签名
func generateXunHuHash(params map[string]string, appSecret string) string {
	// 按 key ASCII 排序
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "hash" || params[k] == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 拼接
	var builder strings.Builder
	for i, k := range keys {
		if i > 0 {
			builder.WriteString("&")
		}
		builder.WriteString(k)
		builder.WriteString("=")
		builder.WriteString(params[k])
	}
	// 最后拼接密钥
	builder.WriteString(appSecret)

	// MD5
	hash := md5.Sum([]byte(builder.String()))
	return hex.EncodeToString(hash[:])
}

// verifyXunHuHash 验证虎皮椒回调签名
func verifyXunHuHash(params map[string]string, appSecret string) bool {
	hash, ok := params["hash"]
	if !ok || hash == "" {
		return false
	}
	expected := generateXunHuHash(params, appSecret)
	return strings.EqualFold(expected, hash)
}

// RequestXunHuPay 虎皮椒支付请求（替代 RequestEpay）
func RequestXunHuPay(c *gin.Context) {
	var req EpayRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "参数错误"})
		return
	}
	if req.Amount < getMinTopup() {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": fmt.Sprintf("充值数量不能小于 %d", getMinTopup())})
		return
	}

	id := c.GetInt("id")
	group, err := model.GetUserGroup(id, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "获取用户分组失败"})
		return
	}
	payMoney := getPayMoney(req.Amount, group)
	if payMoney < 0.01 {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}

	if !operation_setting.ContainsPayMethod(req.PaymentMethod) {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "支付方式不存在"})
		return
	}

	// 检查配置
	if operation_setting.PayAddress == "" || operation_setting.EpayId == "" || operation_setting.EpayKey == "" {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "当前管理员未配置支付信息"})
		return
	}

	callBackAddress := service.GetCallbackAddress()
	notifyUrl := callBackAddress + "/api/user/epay/notify"
	returnUrl := paymentReturnPath("/console/log")

	tradeNo := fmt.Sprintf("%s%d", common.GetRandomString(6), time.Now().Unix())
	tradeNo = fmt.Sprintf("USR%dNO%s", id, tradeNo)

	// 构造虎皮椒请求参数
	nonceStr := common.GetRandomString(32)
	params := map[string]string{
		"version":        "1.1",
		"appid":          operation_setting.EpayId,
		"trade_order_id": tradeNo,
		"total_fee":      strconv.FormatFloat(payMoney, 'f', 2, 64),
		"title":          fmt.Sprintf("充值%d额度", req.Amount),
		"time":           strconv.FormatInt(time.Now().Unix(), 10),
		"notify_url":     notifyUrl,
		"return_url":     returnUrl,
		"nonce_str":      nonceStr,
	}

	// 生成签名
	params["hash"] = generateXunHuHash(params, operation_setting.EpayKey)

	// JSON POST 请求虎皮椒
	jsonData, _ := json.Marshal(params)
	resp, err := http.Post(operation_setting.PayAddress, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 请求支付失败 user_id=%d trade_no=%s error=%q", id, tradeNo, err.Error()))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "拉起支付失败"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 读取响应失败 user_id=%d trade_no=%s error=%q", id, tradeNo, err.Error()))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "拉起支付失败"})
		return
	}

	logger.LogInfo(c.Request.Context(), fmt.Sprintf("虎皮椒 支付响应 user_id=%d trade_no=%s body=%q", id, tradeNo, string(body)))

	var xhResp XunHuPayResponse
	err = json.Unmarshal(body, &xhResp)
	if err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 解析响应失败 user_id=%d trade_no=%s error=%q body=%q", id, tradeNo, err.Error(), string(body)))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "拉起支付失败"})
		return
	}

	if xhResp.ErrCode != 0 {
		logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 支付请求失败 user_id=%d trade_no=%s errcode=%d errmsg=%s", id, tradeNo, xhResp.ErrCode, xhResp.ErrMsg))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": fmt.Sprintf("支付失败: %s", xhResp.ErrMsg)})
		return
	}

	// 创建订单记录
	amount := req.Amount
	if operation_setting.GetQuotaDisplayType() == operation_setting.QuotaDisplayTypeTokens {
		dAmount := decimal.NewFromInt(int64(amount))
		dQuotaPerUnit := decimal.NewFromFloat(common.QuotaPerUnit)
		amount = dAmount.Div(dQuotaPerUnit).IntPart()
	}
	topUp := &model.TopUp{
		UserId:          id,
		Amount:          amount,
		Money:           payMoney,
		TradeNo:         tradeNo,
		PaymentMethod:   req.PaymentMethod,
		PaymentProvider: model.PaymentProviderEpay,
		CreateTime:      time.Now().Unix(),
		Status:          common.TopUpStatusPending,
	}
	err = topUp.Insert()
	if err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 创建充值订单失败 user_id=%d trade_no=%s error=%q", id, tradeNo, err.Error()))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "创建订单失败"})
		return
	}

	logger.LogInfo(c.Request.Context(), fmt.Sprintf("虎皮椒 充值订单创建成功 user_id=%d trade_no=%s amount=%d money=%.2f", id, tradeNo, req.Amount, payMoney))

	// 返回支付链接（兼容前端格式）
	payUrl := xhResp.URL
	if payUrl == "" {
		payUrl = xhResp.URLQr
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "success",
		"data":    payUrl,
		"url":     payUrl,
	})
}

// XunHuPayNotify 虎皮椒支付回调（替代 EpayNotify）
func XunHuPayNotify(c *gin.Context) {
	if operation_setting.PayAddress == "" || operation_setting.EpayId == "" || operation_setting.EpayKey == "" {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("虎皮椒 webhook 被拒绝 reason=not_configured path=%q client_ip=%s", c.Request.RequestURI, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	// 解析 POST 表单参数
	if err := c.Request.ParseForm(); err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 webhook 表单解析失败 path=%q client_ip=%s error=%q", c.Request.RequestURI, c.ClientIP(), err.Error()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	params := make(map[string]string)
	for k, v := range c.Request.PostForm {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	logger.LogInfo(c.Request.Context(), fmt.Sprintf("虎皮椒 webhook 收到请求 path=%q client_ip=%s params=%q", c.Request.RequestURI, c.ClientIP(), common.GetJsonString(params)))

	// 验证签名
	if !verifyXunHuHash(params, operation_setting.EpayKey) {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("虎皮椒 webhook 验签失败 path=%q client_ip=%s params=%q", c.Request.RequestURI, c.ClientIP(), common.GetJsonString(params)))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	logger.LogInfo(c.Request.Context(), fmt.Sprintf("虎皮椒 webhook 验签成功 path=%q client_ip=%s", c.Request.RequestURI, c.ClientIP()))

	// 获取订单状态
	status := params["status"]
	tradeNo := params["trade_order_id"]

	if status != "OD" {
		// OD=已支付，其他状态忽略
		logger.LogInfo(c.Request.Context(), fmt.Sprintf("虎皮椒 webhook 非支付成功状态 trade_no=%s status=%s client_ip=%s", tradeNo, status, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("success"))
		return
	}

	if tradeNo == "" {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("虎皮椒 webhook 缺少订单号 path=%q client_ip=%s", c.Request.RequestURI, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	LockOrder(tradeNo)
	defer UnlockOrder(tradeNo)

	topUp := model.GetTopUpByTradeNo(tradeNo)
	if topUp == nil {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("虎皮椒 回调订单不存在 trade_no=%s client_ip=%s", tradeNo, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	if topUp.PaymentProvider != model.PaymentProviderEpay {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("虎皮椒 订单支付网关不匹配 trade_no=%s order_provider=%s client_ip=%s", tradeNo, topUp.PaymentProvider, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	if topUp.Status == common.TopUpStatusPending {
		topUp.Status = common.TopUpStatusSuccess
		err := topUp.Update()
		if err != nil {
			logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 更新充值订单失败 trade_no=%s user_id=%d error=%q", tradeNo, topUp.UserId, err.Error()))
			_, _ = c.Writer.Write([]byte("fail"))
			return
		}

		dAmount := decimal.NewFromInt(int64(topUp.Amount))
		dQuotaPerUnit := decimal.NewFromFloat(common.QuotaPerUnit)
		quotaToAdd := int(dAmount.Mul(dQuotaPerUnit).IntPart())
		err = model.IncreaseUserQuota(topUp.UserId, quotaToAdd, true)
		if err != nil {
			logger.LogError(c.Request.Context(), fmt.Sprintf("虎皮椒 更新用户额度失败 trade_no=%s user_id=%d quota_to_add=%d error=%q", tradeNo, topUp.UserId, quotaToAdd, err.Error()))
			_, _ = c.Writer.Write([]byte("fail"))
			return
		}

		logger.LogInfo(c.Request.Context(), fmt.Sprintf("虎皮椒 充值成功 trade_no=%s user_id=%d quota_to_add=%d money=%.2f client_ip=%s", tradeNo, topUp.UserId, quotaToAdd, topUp.Money, c.ClientIP()))
		model.RecordTopupLog(topUp.UserId, fmt.Sprintf("使用在线充值成功，充值金额: %v，支付金额：%f", logger.LogQuota(quotaToAdd), topUp.Money), c.ClientIP(), topUp.PaymentMethod, "xunhupay")
	}

	_, _ = c.Writer.Write([]byte("success"))
}

// isXunHuPayEnabled 检查虎皮椒是否已配置
func isXunHuPayEnabled() bool {
	return operation_setting.PayAddress != "" && operation_setting.EpayId != "" && operation_setting.EpayKey != ""
}


