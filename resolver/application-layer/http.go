package applicationlayer

import (
	"encoding/hex"
	"packet-inspector/resolver"
	"strconv"
	"strings"
)

type HTTPType uint8

const (
	HTTP_REQUEST  HTTPType = 0
	HTTP_RESPONSE HTTPType = 1
)

type HTTP struct {
	resolver.IPacket
	// 原始报文
	raw []byte
	// HTTP 类型（请求/响应）
	packetType HTTPType
	// 请求方法
	method string
	// 请求地址
	url string
	// HTTP 版本
	version string
	// 状态码
	statusCode uint16
	// 状态码描述
	statusMessage string
	// 请求头
	headers map[string]string
	// 载荷
	body []byte
}

func (http *HTTP) Raw() []byte {
	return http.raw
}

func (http *HTTP) Hex() string {
	return strings.ToUpper(hex.EncodeToString(http.raw))
}

func (http *HTTP) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Protocol: HTTP (Application)\n")

	if http.packetType == HTTP_REQUEST {
		builder.Write(tabs)
		builder.WriteString("Method: ")
		builder.WriteString(http.method)
		builder.WriteByte('\n')

		builder.Write(tabs)
		builder.WriteString("URL: ")
		builder.WriteString(http.url)
		builder.WriteByte('\n')

		builder.Write(tabs)
		builder.WriteString("Version: ")
		builder.WriteString(http.version)
		builder.WriteByte('\n')
	} else {
		builder.Write(tabs)
		builder.WriteString("Version: ")
		builder.WriteString(http.version)
		builder.WriteByte('\n')

		builder.Write(tabs)
		builder.WriteString("Status code: ")
		builder.WriteString(strconv.Itoa(int(http.statusCode)))
		builder.WriteByte('\n')

		builder.Write(tabs)
		builder.WriteString("Status message: ")
		builder.WriteString(http.statusMessage)
		builder.WriteByte('\n')
	}

	builder.Write(tabs)
	builder.WriteString("Headers: {\n")
	for k, v := range http.headers {
		builder.Write(tabs)
		builder.WriteByte('\t')
		builder.WriteString(k)
		builder.WriteString(": ")
		builder.WriteString(v)
		builder.WriteByte('\n')
	}
	builder.Write(tabs)
	builder.WriteString("}\n")

	builder.Write(tabs)
	builder.WriteString("Payload: {\n")
	builder.Write(tabs)
	builder.WriteString("\tRaw: ")
	if len(http.body) != 0 {
		builder.WriteString(strings.ToUpper(hex.EncodeToString(http.body)))
	} else {
		builder.WriteString("(No Body)")
	}
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("\tReadable text: ")
	if len(http.body) != 0 {
		builder.WriteString(string(http.body))
	} else {
		builder.WriteString("(No Body)")
	}
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("}\n")

	return builder.String()
}

func HTTPResolve(packet []byte) resolver.IPacket {
	http := new(HTTP)
	header, body, founded := strings.Cut(string(packet), "\r\n\r\n")
	if !founded {
		return nil
	}

	line, headers, founded := strings.Cut(header, "\r\n")
	if !founded {
		return nil
	}

	temp := strings.Split(line, " ")
	if len(temp) != 3 {
		return nil
	}

	if strings.HasPrefix(temp[0], "HTTP") {
		http.packetType = HTTP_RESPONSE
		http.version = temp[0]
		statusCode, err := strconv.Atoi(temp[1])
		if err != nil {
			return nil
		}
		http.statusCode = uint16(statusCode)
		http.statusMessage = temp[2]
	} else {
		http.packetType = HTTP_REQUEST
		http.method = temp[0]
		http.url = temp[1]
		http.version = temp[2]
	}

	http.headers = map[string]string{}
	lines := strings.Split(headers, "\r\n")
	for _, line := range lines {
		key, value, founded := strings.Cut(line, ":")
		if !founded {
			return nil
		}
		http.headers[key] = strings.Trim(value, " ")
	}

	http.body = []byte(body)
	http.raw = make([]byte, len(packet))
	copy(http.raw, packet)

	return http
}
