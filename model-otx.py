package model

type Indicator struct {
	IocID string `json:"ioc_id"`
	Ioc string `json:"ioc"`
	IocType string `json:"ioc_type"`
	CreatedTime string `json:"created_time"`
	CrawledTime string `json:"crawled_time"`
	Source string `json:"source"`
	Category []string `json:"category"`
}


type Post struct {
	PulseID string `json:"pulse_id"`
	Name string `json:"name"`
	Description string `json:"description"`
	AuthorName string `json:"author_name"`
	Modified string `json:"modified"`
	Created string `json:"created"`
	TargetedCountries []string `json:"targeted_countries"`
	Industries []string `json:"industries"`
	MalwareFamilies []string `json:"malware_families"`
	AttackIds []string `json:"attack_ids"`
	References string `json:"references"`
	Category []string `json:"category"`
}
