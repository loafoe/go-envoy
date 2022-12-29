package envoy

type LoginResponse struct {
	Message      string `json:"message"`
	SessionId    string `json:"session_id"`
	ManagerToken string `json:"manager_token"`
	IsConsumer   bool   `json:"is_consumer"`
}

type ProductionResponse struct {
	Production  []Measurement `json:"production"`
	Consumption []Measurement `json:"consumption"`
	Storage     []Storage     `json:"storage"`
}

type Storage struct {
	Type        string `json:"type"`
	ActiveCount int    `json:"activeCount"`
	ReadingTime int    `json:"readingTime"`
	WNow        int    `json:"wNow"`
	WhNow       int    `json:"whNow"`
	State       string `json:"state"`
}

type Measurement struct {
	Type             string  `json:"type"`
	ActiveCount      int     `json:"activeCount"`
	ReadingTime      int     `json:"readingTime"`
	WNow             float64 `json:"wNow"`
	WhLifetime       int     `json:"whLifetime"`
	MeasurementType  string  `json:"measurementType,omitempty"`
	VarhLeadLifetime int     `json:"varhLeadLifetime,omitempty"`
	VarhLagLifetime  int     `json:"varhLagLifetime,omitempty"`
	VahLifetime      int     `json:"vahLifetime,omitempty"`
	RmsCurrent       float64 `json:"rmsCurrent,omitempty"`
	RmsVoltage       float64 `json:"rmsVoltage,omitempty"`
	ReactPwr         float64 `json:"reactPwr,omitempty"`
	ApprntPwr        float64 `json:"apprntPwr,omitempty"`
	PwrFactor        float64 `json:"pwrFactor,omitempty"`
	WhToday          int     `json:"whToday,omitempty"`
	WhLastSevenDays  int     `json:"whLastSevenDays,omitempty"`
	VahToday         int     `json:"vahToday,omitempty"`
	VarhLeadToday    int     `json:"varhLeadToday,omitempty"`
	VarhLagToday     int     `json:"varhLagToday,omitempty"`
	Lines            []Line  `json:"lines,omitempty"`
}

type Line struct {
	WNow             float64 `json:"wNow"`
	WhLifetime       int     `json:"whLifetime"`
	VarhLeadLifetime int     `json:"varhLeadLifetime"`
	VarhLagLifetime  int     `json:"varhLagLifetime"`
	VahLifetime      int     `json:"vahLifetime"`
	RmsCurrent       float64 `json:"rmsCurrent"`
	RmsVoltage       float64 `json:"rmsVoltage"`
	ReactPwr         float64 `json:"reactPwr"`
	ApprntPwr        float64 `json:"apprntPwr"`
	PwrFactor        float64 `json:"pwrFactor"`
	WhToday          int     `json:"whToday"`
	WhLastSevenDays  int     `json:"whLastSevenDays"`
	VahToday         int     `json:"vahToday"`
	VarhLeadToday    int     `json:"varhLeadToday"`
	VarhLagToday     int     `json:"varhLagToday"`
}

type TokenResponse struct {
	GenerationTime int64  `json:"generation_time"`
	Token          string `json:"token"`
	ExpiresAt      int64  `json:"expires_at"`
}
