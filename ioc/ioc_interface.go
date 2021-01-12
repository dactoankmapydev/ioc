package ioc

import "ioc-provider/model"

// IocProvider là interface để service implement các hàm
type IocProvider interface {
	GetHuntingNotificationFiles() ([]model.VrttInfo, error)
}
