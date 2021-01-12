package ioc

import "ioc-provider/model"

// IocProvider là interface để service implement các hàm
type IocProvider interface {
	GetHuntingNotificationFiles() ([]VrttInfo, error)
}

type VrttInfo struct {
	Name string `json:"names"`
	Sha256 string `json:"sha256"`
	Sha1 string `json:"sha1"`
	Md5 string `json:"md5"`
	FirstSubmit int `json:"first_submit"`
	NotificationDate int `json:"notification_date"`
	FileType string `json:"file_type"`
	Tags []string `json:"tags"`
	EnginesDetected []string `json:"engines_detected"`
	Detected int `json:"detected"`
	Point int `json:"point"`
}
