package license

import (
	"Glue-API/utils"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

type License_type struct {
	ExpiryDate string `json:"expired"`
}

func License() (output []string, err error) {
	var stdout []byte

	// name
	cmd := exec.Command("sh", "-c", "cat /root/license_test | grep 'name' | awk '{print $3}'")
	stdout, err = cmd.CombinedOutput()
	if err != nil {
		err_str := strings.ReplaceAll(string(stdout), "\n", "")
		err = errors.New(err_str)
		utils.FancyHandleError(err)
		return
	}
	license_info := strings.ReplaceAll(string(stdout), "\n", "")
	output = append(output, string(license_info))

	// type
	cmd = exec.Command("sh", "-c", "cat /root/license_test | grep 'type' | awk '{print $3}'")
	stdout, err = cmd.CombinedOutput()
	if err != nil {
		err_str := strings.ReplaceAll(string(stdout), "\n", "")
		err = errors.New(err_str)
		utils.FancyHandleError(err)
		return
	}
	licenseType := strings.ReplaceAll(string(stdout), "\n", "")
	output = append(output, licenseType)

	// core (type에 "vm"이 포함된 경우에만)
	if strings.Contains(strings.ToLower(licenseType), "vm") {
		cmd = exec.Command("sh", "-c", "cat /root/license_test | grep 'core' | awk '{print $3}'")
		stdout, err = cmd.CombinedOutput()
		if err != nil {
			err_str := strings.ReplaceAll(string(stdout), "\n", "")
			err = errors.New(err_str)
			utils.FancyHandleError(err)
			return
		}
		license_info = strings.ReplaceAll(string(stdout), "\n", "")
		output = append(output, string(license_info))
	} else {
		// vm이 아닌 경우 core 값을 빈 문자열로 추가
		output = append(output, "")
	}

	// date
	cmd = exec.Command("sh", "-c", "cat /root/license_test | grep 'date' | awk '{print $3}'")
	stdout, err = cmd.CombinedOutput()
	if err != nil {
		err_str := strings.ReplaceAll(string(stdout), "\n", "")
		err = errors.New(err_str)
		utils.FancyHandleError(err)
		return
	}
	license_info = strings.ReplaceAll(string(stdout), "\n", "")
	output = append(output, string(license_info))

	return
}

// GenerateKeyAndIV는 password와 salt를 사용하여 key와 iv를 생성합니다
func GenerateKeyAndIV(password, salt string) (key []byte, iv []byte, err error) {
	// key 생성 (32 bytes)
	key, err = scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("key 생성 실패: %v", err)
	}

	// iv 생성 (16 bytes)
	iv, err = scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("iv 생성 실패: %v", err)
	}

	return key, iv, nil
}

// GetExpirationDate는 라이센스 파일에서 만료일을 가져옵니다
func GetExpirationDate(password, salt string) (string, error) {
	// key와 iv 생성
	key, iv, err := GenerateKeyAndIV(password, salt)
	if err != nil {
		return "", fmt.Errorf("key/iv 생성 실패: %v", err)
	}

	// 가장 최근 라이센스 파일 경로 가져오기
	latestLicense, err := getLatestLicenseFile("/root")
	if err != nil {
		return "", fmt.Errorf("최신 라이센스 파일 찾기 실패: %v", err)
	}

	// 라이센스 파일 읽기
	licenseData, err := ioutil.ReadFile(latestLicense)
	if err != nil {
		return "", fmt.Errorf("라이센스 파일 읽기 실패: %v", err)
	}

	// base64 디코딩
	ciphertext, err := base64.StdEncoding.DecodeString(string(licenseData))
	if err != nil {
		return "", fmt.Errorf("라이센스 파일 디코딩 실패: %v", err)
	}

	// AES 복호화 블록 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("암호화 블록 생성 실패: %v", err)
	}

	// CBC 모드로 복호화
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS7 패딩 제거
	length := len(plaintext)
	if length == 0 {
		return "", fmt.Errorf("복호화된 데이터가 비어있습니다")
	}
	unpadding := int(plaintext[length-1])
	if unpadding > length {
		return "", fmt.Errorf("잘못된 패딩")
	}
	plaintext = plaintext[:(length - unpadding)]

	// License_type으로 직접 파싱
	var license License_type
	if err := json.Unmarshal(plaintext, &license); err != nil {
		return "", fmt.Errorf("라이센스 JSON 파싱 실패: %v", err)
	}

	if license.ExpiryDate == "" {
		return "", fmt.Errorf("expired 필드를 찾을 수 없음")
	}

	log.Printf("추출된 만료일: %s", license.ExpiryDate)
	return license.ExpiryDate, nil
}

// CheckLicenseExpiration은 라이센스 만료 여부를 확인하고 호스트 에이전트를 제어합니다
func CheckLicenseExpiration(expirationDate string) {
	// 최초 실행 시 만료 여부 확인
	expired := isLicenseExpired(expirationDate)
	ControlHostAgent(expired)
}

// isLicenseExpired는 라이센스 만료 여부를 확인합니다
func isLicenseExpired(expirationDate string) bool {
	// 현재 시간 (자정 기준)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	// 만료일 파싱
	expDate, err := time.Parse("2006-01-02", expirationDate)
	if err != nil {
		log.Printf("만료일 파싱 실패: %v\n", err)
		return true // 파싱 실패시 만료된 것으로 처리
	}

	// 만료일이 오늘 이후면 유효함 (만료일 당일까지 유효)
	return today.After(expDate)
}

// controlHostAgent는 호스트 에이전트를 제어합니다
func ControlHostAgent(flag bool) {
	var cmd *exec.Cmd
	var action string

	if flag {
		// Mold Agent 시작
		cmd = exec.Command("systemctl", "start", "mold-agent")
		action = "시작"
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		log.Printf("[%s] 라이센스 유효: 호스트 에이전트를 %s합니다", currentTime, action)
	} else {
		// Mold Agent 정지
		cmd = exec.Command("systemctl", "stop", "mold-agent")
		action = "정지"
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		log.Printf("[%s] 라이센스 만료: 호스트 에이전트를 %s합니다", currentTime, action)
	}

	if err := cmd.Run(); err != nil {
		log.Printf("호스트 에이전트 %s 실패: %v", action, err)
	}
}

// IsLicenseExpired는 라이센스 만료일을 체크합니다
func IsLicenseExpired(password, salt string) (bool, error) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	log.Printf("[%s] 라이센스 체크 시작", currentTime)

	// 만료일 가져오기
	expirationDate, err := GetExpirationDate(password, salt)

	if err != nil {
		// 라이센스 파일이 없거나 읽을 수 없는 경우 true 반환
		return true, nil
	}

	// 만료 여부 확인
	expired := isLicenseExpired(expirationDate)
	return expired, nil
}

func getHostUUID() (string, error) {
	// /etc/machine-id 파일에서 UUID 읽기
	data, err := ioutil.ReadFile("/etc/machine-id")
	if err != nil {
		return "", fmt.Errorf("호스트 UUID를 읽을 수 없습니다: %v", err)
	}

	// 공백 제거 및 문자열 반환
	uuid := strings.TrimSpace(string(data))
	if uuid == "" {
		return "", fmt.Errorf("호스트 UUID가 비어있습니다")
	}

	return uuid, nil
}

// 라이센스 파일을 찾는 함수
func getLatestLicenseFile(_ string) (string, error) {
	// 호스트 UUID 읽기
	hostUUID, err := getHostUUID()
	if err != nil {
		return "", err
	}
	log.Printf("호스트 UUID: %s", hostUUID)

	// 라이센스 파일 경로 생성
	licensePath := filepath.Join("/usr/share", hostUUID)
	log.Printf("라이센스 디렉토리 경로: %s", licensePath)

	// 디렉토리 존재 여부 확인
	if _, err := os.Stat(licensePath); os.IsNotExist(err) {
		return "", fmt.Errorf("라이센스 디렉토리를 찾을 수 없습니다: %s", licensePath)
	}

	files, err := ioutil.ReadDir(licensePath)
	if err != nil {
		return "", err
	}

	if len(files) == 0 {
		return "", fmt.Errorf("라이센스 파일을 찾을 수 없습니다: %s", licensePath)
	}

	// 가장 최근 파일 찾기
	var latestFile os.FileInfo
	for _, file := range files {
		if latestFile == nil || file.ModTime().After(latestFile.ModTime()) {
			latestFile = file
		}
	}

	finalPath := filepath.Join(licensePath, latestFile.Name())
	log.Printf("찾은 라이센스 파일 경로: %s", finalPath)

	return finalPath, nil
}
