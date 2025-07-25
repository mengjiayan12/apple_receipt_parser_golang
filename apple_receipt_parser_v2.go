package util

import (
	"encoding/base64"
	"fmt"
	"regexp"
)

// 常量定义 - 对应Python代码中的常量 
// Constants definition - corresponding to constants in Python code
const (
	PKCS7_OID                       = "1.2.840.113549.1.7.2"
	IN_APP_ARRAY                    = 17
	TRANSACTION_IDENTIFIER          = 1703
	ORIGINAL_TRANSACTION_IDENTIFIER = 1705
)

// ASN.1 类型常量 - 对应Python asn1.Types 
// ASN.1 type constants - corresponding to Python asn1.Types
const (
	ASN1_PRIMITIVE   = 0
	ASN1_CONSTRUCTED = 1
)

// ASN.1 标签常量 - 对应Python asn1.Numbers 
// ASN.1 tag constants - corresponding to Python asn1.Numbers
const (
	ASN1_SEQUENCE     = 16
	ASN1_SET          = 17
	ASN1_INTEGER      = 2
	ASN1_OCTET_STRING = 4
	ASN1_OID          = 6
)

// ReceiptUtility Apple收据解析工具 
// ReceiptUtility Apple receipt parsing utility
type ReceiptUtility struct {
}

// NewReceiptUtility 创建新的收据解析工具实例 
// NewReceiptUtility creates a new receipt parsing utility instance
func NewReceiptUtility() *ReceiptUtility {
	return &ReceiptUtility{}
}

// ExtractTransactionIdFromAppReceipt 从编码的App Receipt中提取交易ID
// 完全按照Python代码逻辑实现
// ExtractTransactionIdFromAppReceipt extracts transaction ID from encoded App Receipt
// Fully implemented according to Python code logic
func (r *ReceiptUtility) ExtractTransactionIdFromAppReceipt(appReceipt string) (string, error) {
	decoder := NewIndefiniteFormAwareDecoder()

	receiptData, err := base64.StdEncoding.DecodeString(appReceipt)
	if err != nil {
		return "", fmt.Errorf("base64解码失败 / base64 decoding failed: %v", err)
	}

	decoder.Start(receiptData)

	tag, err := decoder.Peek()
	if err != nil {
		return "", err
	}

	if tag.TagType != ASN1_CONSTRUCTED || tag.TagNumber != ASN1_SEQUENCE {
		return "", fmt.Errorf("不是有效的SEQUENCE / not a valid SEQUENCE")
	}

	err = decoder.Enter()
	if err != nil {
		return "", err
	}

	// PKCS#7 object
	tag, value, err := decoder.Read()
	if err != nil {
		return "", err
	}

	if tag.TagType != ASN1_PRIMITIVE || tag.TagNumber != ASN1_OID {
		return "", fmt.Errorf("期望OID标签 / expecting OID tag")
	}

	// 验证OID值（不使用标准库解析） / Verify OID value (without using standard library parsing)
	oidStr := r.parseOID(value)
	if oidStr != PKCS7_OID {
		return "", fmt.Errorf("OID不匹配PKCS#7格式 / OID does not match PKCS#7 format")
	}

	// This is the PKCS#7 format, work our way into the inner content
	// 这是PKCS#7格式，深入到内部内容 / This is the PKCS#7 format, work our way into the inner content
	err = decoder.Enter()
	if err != nil {
		return "", err
	}

	err = decoder.Enter()
	if err != nil {
		return "", err
	}

	_, _, err = decoder.Read()
	if err != nil {
		return "", err
	}

	_, _, err = decoder.Read()
	if err != nil {
		return "", err
	}

	err = decoder.Enter()
	if err != nil {
		return "", err
	}

	_, _, err = decoder.Read()
	if err != nil {
		return "", err
	}

	err = decoder.Enter()
	if err != nil {
		return "", err
	}

	tag, value, err = decoder.Read()
	if err != nil {
		return "", err
	}

	// Xcode uses nested OctetStrings, we extract the inner string in this case
	// Xcode使用嵌套的OctetStrings，在这种情况下我们提取内部字符串 / Xcode uses nested OctetStrings, we extract the inner string in this case
	if tag.TagType == ASN1_CONSTRUCTED && tag.TagNumber == ASN1_OCTET_STRING {
		innerDecoder := NewIndefiniteFormAwareDecoder()
		innerDecoder.Start(value)
		tag, value, err = innerDecoder.Read()
		if err != nil {
			return "", err
		}
	}

	if tag.TagType != ASN1_PRIMITIVE || tag.TagNumber != ASN1_OCTET_STRING {
		return "", fmt.Errorf("期望OCTET STRING / expecting OCTET STRING")
	}

	decoder = NewIndefiniteFormAwareDecoder()
	decoder.Start(value)

	tag, err = decoder.Peek()
	if err != nil {
		return "", err
	}

	if tag.TagType != ASN1_CONSTRUCTED || tag.TagNumber != ASN1_SET {
		return "", fmt.Errorf("期望SET / expecting SET")
	}

	err = decoder.Enter()
	if err != nil {
		return "", err
	}

	// We are in the top-level sequence, work our way to the array of in-apps
	// 我们在顶级序列中，寻找应用内购买数组 
	// We are in the top-level sequence, work our way to the array of in-apps
	for !decoder.EOF() {
		err = decoder.Enter()
		if err != nil {
			return "", err
		}

		tag, value, err := decoder.Read()
		if err != nil {
			decoder.Leave()
			continue
		}

		if tag.TagType == ASN1_PRIMITIVE && tag.TagNumber == ASN1_INTEGER {
			intValue := r.parseInteger(value)

			if intValue == IN_APP_ARRAY {
				_, _, err = decoder.Read()
				if err != nil {
					decoder.Leave()
					continue
				}

				tag, value, err = decoder.Read()
				if err != nil {
					decoder.Leave()
					continue
				}

				if tag.TagType != ASN1_PRIMITIVE || tag.TagNumber != ASN1_OCTET_STRING {
					decoder.Leave()
					continue
				}

				inappDecoder := NewIndefiniteFormAwareDecoder()
				inappDecoder.Start(value)

				err = inappDecoder.Enter()
				if err != nil {
					decoder.Leave()
					continue
				}

				// In-app array / 应用内购买数组
				for !inappDecoder.EOF() {
					err = inappDecoder.Enter()
					if err != nil {
						continue
					}

					tag, value, err := inappDecoder.Read()
					if err != nil {
						inappDecoder.Leave()
						continue
					}

					if tag.TagType == ASN1_PRIMITIVE && tag.TagNumber == ASN1_INTEGER {
						intValue := r.parseInteger(value)

						if intValue == TRANSACTION_IDENTIFIER || intValue == ORIGINAL_TRANSACTION_IDENTIFIER {
							_, _, err = inappDecoder.Read()
							if err != nil {
								inappDecoder.Leave()
								continue
							}

							tag, value, err = inappDecoder.Read()
							if err != nil {
								inappDecoder.Leave()
								continue
							}

							singletonDecoder := NewIndefiniteFormAwareDecoder()
							singletonDecoder.Start(value)

							tag, value, err = singletonDecoder.Read()
							if err != nil {
								inappDecoder.Leave()
								continue
							}

							return string(value), nil
						}
					}

					inappDecoder.Leave()
				}
			}
		}

		decoder.Leave()
	}

	return "", nil
}

// parseOID 解析OID值（避免使用标准库） 
// parseOID parses OID value (avoiding standard library)
func (r *ReceiptUtility) parseOID(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// 简化的OID解析，仅针对PKCS7_OID 
	// Simplified OID parsing, only for PKCS7_OID
	// PKCS7_OID = "1.2.840.113549.1.7.2"
	// 对应的编码应该是: 42, 134, 72, 134, 247, 13, 1, 7, 2 
	// Corresponding encoding should be: 42, 134, 72, 134, 247, 13, 1, 7, 2
	expected := []byte{42, 134, 72, 134, 247, 13, 1, 7, 2}

	if len(data) == len(expected) {
		for i, b := range expected {
			if data[i] != b {
				return ""
			}
		}
		return PKCS7_OID
	}

	return ""
}

// parseInteger 解析整数值（避免使用标准库） 
// parseInteger parses integer value (avoiding standard library)
func (r *ReceiptUtility) parseInteger(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	result := 0
	for _, b := range data {
		result = (result << 8) | int(b)
	}

	return result
}

// ExtractTransactionIdFromTransactionReceipt 从编码的交易收据中提取交易ID
// ExtractTransactionIdFromTransactionReceipt extracts transaction ID from encoded transaction receipt
func (r *ReceiptUtility) ExtractTransactionIdFromTransactionReceipt(transactionReceipt string) (string, error) {
	decodedTopLevel, err := base64.StdEncoding.DecodeString(transactionReceipt)
	if err != nil {
		return "", fmt.Errorf("base64解码失败 / base64 decoding failed: %v", err)
	}

	decodedTopLevelStr := string(decodedTopLevel)

	// 使用正则表达式匹配 "purchase-info" = "..."; / Use regex to match "purchase-info" = "...";
	purchaseInfoRegex := regexp.MustCompile(`"purchase-info"\s*=\s*"([a-zA-Z0-9+/=]+)";`)
	matchingResult := purchaseInfoRegex.FindStringSubmatch(decodedTopLevelStr)

	if len(matchingResult) > 1 {
		decodedInnerLevel, err := base64.StdEncoding.DecodeString(matchingResult[1])
		if err != nil {
			return "", fmt.Errorf("内层base64解码失败 / inner base64 decoding failed: %v", err)
		}

		decodedInnerLevelStr := string(decodedInnerLevel)

		// 使用正则表达式匹配 "transaction-id" = "..."; / Use regex to match "transaction-id" = "...";
		transactionIdRegex := regexp.MustCompile(`"transaction-id"\s*=\s*"([a-zA-Z0-9+/=]+)";`)
		innerMatchingResult := transactionIdRegex.FindStringSubmatch(decodedInnerLevelStr)

		if len(innerMatchingResult) > 1 {
			return innerMatchingResult[1], nil
		}
	}

	return "", nil
}

// IndefiniteFormAwareDecoder ASN.1解码器，支持indefinite length encoding
// IndefiniteFormAwareDecoder ASN.1 decoder that supports indefinite length encoding
type IndefiniteFormAwareDecoder struct {
	data   []byte
	offset int
	stack  []int
}

// ASN1Tag ASN.1标签结构 / ASN1Tag ASN.1 tag structure
type ASN1Tag struct {
	TagClass  int
	TagType   int // 0=primitive, 1=constructed / 0=原始类型, 1=构造类型
	TagNumber int
}

// NewIndefiniteFormAwareDecoder 创建新的解码器实例 
// NewIndefiniteFormAwareDecoder creates a new decoder instance
func NewIndefiniteFormAwareDecoder() *IndefiniteFormAwareDecoder {
	return &IndefiniteFormAwareDecoder{
		stack: make([]int, 0),
	}
}

// Start 开始解码数据 
// Start begins decoding data
func (d *IndefiniteFormAwareDecoder) Start(data []byte) {
	d.data = data
	d.offset = 0
	d.stack = []int{len(data)}
}

// EOF 检查是否到达数据末尾 
// EOF checks if we've reached the end of data
func (d *IndefiniteFormAwareDecoder) EOF() bool {
	if len(d.stack) == 0 {
		return true
	}
	return d.offset >= d.stack[len(d.stack)-1]
}

// Peek 查看下一个标签而不移动位置 
// Peek looks at the next tag without moving position
func (d *IndefiniteFormAwareDecoder) Peek() (ASN1Tag, error) {
	if d.EOF() {
		return ASN1Tag{}, fmt.Errorf("已到达数据末尾 / reached end of data")
	}

	savedOffset := d.offset
	tag, err := d.readTag()
	d.offset = savedOffset

	return tag, err
}

// Enter 进入复合类型 
// Enter enters a compound type
func (d *IndefiniteFormAwareDecoder) Enter() error {
	tag, err := d.readTag()
	if err != nil {
		return err
	}

	if tag.TagType != ASN1_CONSTRUCTED {
		return fmt.Errorf("尝试进入非复合类型 / attempting to enter non-compound type")
	}

	length, err := d.readLength()
	if err != nil {
		return err
	}

	// 将新的边界推入栈 / Push new boundary onto stack
	d.stack = append(d.stack, d.offset+length)

	return nil
}

// Leave 离开当前复合类型 
// Leave exits the current compound type
func (d *IndefiniteFormAwareDecoder) Leave() {
	if len(d.stack) > 1 {
		d.offset = d.stack[len(d.stack)-1]
		d.stack = d.stack[:len(d.stack)-1]
	}
}

// Read 读取下一个元素 
// Read reads the next element
func (d *IndefiniteFormAwareDecoder) Read() (ASN1Tag, []byte, error) {
	tag, err := d.readTag()
	if err != nil {
		return ASN1Tag{}, nil, err
	}

	length, err := d.readLength()
	if err != nil {
		return ASN1Tag{}, nil, err
	}

	if d.offset+length > len(d.data) {
		return ASN1Tag{}, nil, fmt.Errorf("数据长度不足 / insufficient data length")
	}

	value := d.data[d.offset : d.offset+length]
	d.offset += length

	return tag, value, nil
}

// readTag 读取ASN.1标签 
// readTag reads ASN.1 tag
func (d *IndefiniteFormAwareDecoder) readTag() (ASN1Tag, error) {
	if d.offset >= len(d.data) {
		return ASN1Tag{}, fmt.Errorf("数据过早结束 / premature end of data")
	}

	b := d.data[d.offset]
	d.offset++

	tag := ASN1Tag{
		TagClass:  int((b & 0xC0) >> 6),
		TagType:   int((b & 0x20) >> 5), // 0=primitive, 1=constructed / 0=原始类型, 1=构造类型
		TagNumber: int(b & 0x1F),
	}

	// 处理高标签号 / Handle high tag numbers
	if tag.TagNumber == 0x1F {
		tag.TagNumber = 0
		for {
			if d.offset >= len(d.data) {
				return ASN1Tag{}, fmt.Errorf("数据过早结束 / premature end of data")
			}

			b = d.data[d.offset]
			d.offset++

			tag.TagNumber = (tag.TagNumber << 7) | int(b&0x7F)

			if (b & 0x80) == 0 {
				break
			}
		}
	}

	return tag, nil
}

// readLength 读取长度，支持indefinite length encoding
// 完全按照Python中的_read_length方法实现
// readLength reads length, supporting indefinite length encoding
// Fully implemented according to Python's _read_length method
func (d *IndefiniteFormAwareDecoder) readLength() (int, error) {
	if d.offset >= len(d.data) {
		return 0, fmt.Errorf("数据过早结束 / premature end of data")
	}

	b := d.data[d.offset]

	if b == 0x80 {
		// Xcode receipts use indefinite length encoding, not supported by all parsers
		// Indefinite length encoding is only entered, but never left during parsing for receipts
		// We therefore round up indefinite length encoding to be the remaining length
		// Xcode收据使用indefinite length encoding，大多数解析器不支持
		// Indefinite length encoding只进入，在收据解析过程中从不离开
		// 因此我们将indefinite length encoding向上舍入为剩余长度
		d.offset++ // 对应Python的self._read_byte() / Corresponds to Python's self._read_byte()

		// 返回剩余数据的长度（对应Python的len(input_data) - index）
		// Return the length of remaining data (corresponds to Python's len(input_data) - index)
		if len(d.stack) > 0 {
			return d.stack[len(d.stack)-1] - d.offset, nil
		}
		return len(d.data) - d.offset, nil
	}

	d.offset++

	if (b & 0x80) == 0 {
		// 短格式 / Short form
		return int(b), nil
	}

	// 长格式 / Long form
	lengthOfLength := int(b & 0x7F)
	if lengthOfLength == 0 {
		return 0, fmt.Errorf("不支持indefinite length encoding的标准形式 / standard form of indefinite length encoding not supported")
	}

	if d.offset+lengthOfLength > len(d.data) {
		return 0, fmt.Errorf("数据过早结束 / premature end of data")
	}

	length := 0
	for i := 0; i < lengthOfLength; i++ {
		length = (length << 8) | int(d.data[d.offset])
		d.offset++
	}

	return length, nil
}