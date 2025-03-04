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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

type License_type struct {
	ExpiryDate string `json:"expiry_date"`
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
		return "", fmt.Errorf("expiry_date 필드를 찾을 수 없음")
	}

	log.Printf("추출된 만료일: %s", license.ExpiryDate)
	return license.ExpiryDate, nil
}

// CheckLicenseExpiration은 라이센스 만료 여부를 확인하고 호스트 에이전트를 제어합니다
func CheckLicenseExpiration(expirationDate string) {
	// 최초 실행 시 만료 여부 확인
	expired := isLicenseExpired(expirationDate)
	controlHostAgent(expired)

	// 만료된 경우에만 10분마다 체크
	if expired {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			expired = isLicenseExpired(expirationDate)
			controlHostAgent(expired)
			log.Printf("라이센스 체크 완료: 만료=%v", expired)
		}
	}
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
func controlHostAgent(expired bool) {
	var cmd *exec.Cmd
	var action string

	if expired {
		// 만료되었으면 정지
		cmd = exec.Command("systemctl", "stop", "mold-agent")
		action = "정지"
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		log.Printf("[%s] 라이센스 만료: 호스트 에이전트를 %s합니다", currentTime, action)
	} else {
		// 유효하면 시작 (최초 실행 시에만)
		cmd = exec.Command("systemctl", "start", "mold-agent")
		action = "시작"
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		log.Printf("[%s] 라이센스 유효: 호스트 에이전트를 %s합니다", currentTime, action)
	}

	if err := cmd.Run(); err != nil {
		log.Printf("호스트 에이전트 %s 실패: %v", action, err)
	}
}

// StartLicenseCheck는 라이센스 체크를 시작합니다
func StartLicenseCheck(password, salt string) error {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	log.Printf("[%s] 라이센스 체크 시작", currentTime)

	// 만료일 가져오기
	expirationDate, err := GetExpirationDate(password, salt)
	if err != nil {
		currentTime = time.Now().Format("2006-01-02 15:04:05")
		log.Printf("[%s] 라이센스 파일이 없거나 읽을 수 없습니다: %v", currentTime, err)
		log.Printf("[%s] 라이센스 파일이 없어 호스트 에이전트를 정지합니다.", currentTime)

		// 라이센스 파일이 없는 경우 호스트 에이전트 정지
		cmd := exec.Command("systemctl", "stop", "mold-agent")
		if err := cmd.Run(); err != nil {
			log.Printf("[%s] 호스트 에이전트 정지 실패: %v", currentTime, err)
		}

		// 10분마다 로그 출력
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			currentTime = time.Now().Format("2006-01-02 15:04:05")
			log.Printf("[%s] 라이센스 파일이 없어 호스트 에이전트를 정지합니다.", currentTime)
		}
		return nil
	}

	// 만료 여부 확인
	expired := isLicenseExpired(expirationDate)
	if !expired {
		// 유효한 경우 최초 한 번만 에이전트 시작
		currentTime = time.Now().Format("2006-01-02 15:04:05")
		log.Printf("[%s] 라이센스 유효: 호스트 에이전트를 시작합니다", currentTime)
		cmd := exec.Command("systemctl", "start", "mold-agent")
		if err := cmd.Run(); err != nil {
			log.Printf("호스트 에이전트 시작 실패: %v", err)
		}
	}

	// 라이센스 체크 시작
	CheckLicenseExpiration(expirationDate)
	return nil
}

// 가장 최근 라이센스 파일을 찾고 .lic 파일로 변환하는 함수
func getLatestLicenseFile(dirPath string) (string, error) {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return "", err
	}

	var latestFile string
	var latestTime time.Time

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".lic") {
			if latestFile == "" || file.ModTime().After(latestTime) {
				latestFile = filepath.Join(dirPath, file.Name())
				latestTime = file.ModTime()
			}
		}
	}

	if latestFile == "" {
		return "", fmt.Errorf("라이센스 파일을 찾을 수 없습니다")
	}

	return latestFile, nil
}
