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
	Type        string  `json:"type"`
	ActiveCount int     `json:"activeCount"`
	ReadingTime int     `json:"readingTime"`
	WNow        float64 `json:"wNow"`
	WhNow       float64 `json:"whNow"`
	State       string  `json:"state"`
}

type Measurement struct {
	Type             string  `json:"type"`
	ActiveCount      int     `json:"activeCount"`
	ReadingTime      int     `json:"readingTime"`
	WNow             float64 `json:"wNow"`
	WhLifetime       float64 `json:"whLifetime"`
	MeasurementType  string  `json:"measurementType,omitempty"`
	VarhLeadLifetime float64 `json:"varhLeadLifetime,omitempty"`
	VarhLagLifetime  float64 `json:"varhLagLifetime,omitempty"`
	VahLifetime      float64 `json:"vahLifetime,omitempty"`
	RmsCurrent       float64 `json:"rmsCurrent,omitempty"`
	RmsVoltage       float64 `json:"rmsVoltage,omitempty"`
	ReactPwr         float64 `json:"reactPwr,omitempty"`
	ApprntPwr        float64 `json:"apprntPwr,omitempty"`
	PwrFactor        float64 `json:"pwrFactor,omitempty"`
	WhToday          float64 `json:"whToday,omitempty"`
	WhLastSevenDays  float64 `json:"whLastSevenDays,omitempty"`
	VahToday         float64 `json:"vahToday,omitempty"`
	VarhLeadToday    float64 `json:"varhLeadToday,omitempty"`
	VarhLagToday     float64 `json:"varhLagToday,omitempty"`
	Lines            []Line  `json:"lines,omitempty"`
}

type Line struct {
	WNow             float64 `json:"wNow"`
	WhLifetime       float64 `json:"whLifetime"`
	VarhLeadLifetime float64 `json:"varhLeadLifetime"`
	VarhLagLifetime  float64 `json:"varhLagLifetime"`
	VahLifetime      float64 `json:"vahLifetime"`
	RmsCurrent       float64 `json:"rmsCurrent"`
	RmsVoltage       float64 `json:"rmsVoltage"`
	ReactPwr         float64 `json:"reactPwr"`
	ApprntPwr        float64 `json:"apprntPwr"`
	PwrFactor        float64 `json:"pwrFactor"`
	WhToday          float64 `json:"whToday"`
	WhLastSevenDays  float64 `json:"whLastSevenDays"`
	VahToday         float64 `json:"vahToday"`
	VarhLeadToday    float64 `json:"varhLeadToday"`
	VarhLagToday     float64 `json:"varhLagToday"`
}

type TokenResponse struct {
	GenerationTime int64  `json:"generation_time"`
	Token          string `json:"token"`
	ExpiresAt      int64  `json:"expires_at"`
}

type Inverter struct {
	SerialNumber    string `json:"serialNumber"`
	LastReportDate  int    `json:"lastReportDate"`
	DevType         int    `json:"devType"`
	LastReportWatts int    `json:"lastReportWatts"`
	MaxReportWatts  int    `json:"maxReportWatts"`
}
type CommCheckResponse map[string]int

type DiscoverResponse struct {
	IPV4         string
	IPV6         string
	Serial       string
	ProtoVersion string
}

type InventoryResponse []struct {
	Batteries []Battery `json:"devices"`
	Type      string    `json:"type"`
}

type Battery struct {
	EnchgGridMode        string   `json:"Enchg_grid_mode,omitempty"`
	EnpwrCurrStateID     int      `json:"Enpwr_curr_state_id,omitempty"`
	EnpwrGridMode        string   `json:"Enpwr_grid_mode,omitempty"`
	EnpwrRelayStateBm    int      `json:"Enpwr_relay_state_bm,omitempty"`
	AdminState           int      `json:"admin_state"`
	AdminStateStr        string   `json:"admin_state_str"`
	BmuFwVersion         string   `json:"bmu_fw_version,omitempty"`
	CommLevel24Ghz       int      `json:"comm_level_2_4_ghz"`
	CommLevelSubGhz      int      `json:"comm_level_sub_ghz"`
	Communicating        bool     `json:"communicating"`
	CreatedDate          int      `json:"created_date"`
	DcSwitchOff          bool     `json:"dc_switch_off"`
	DerIndex             int      `json:"der_index,omitempty"`
	DeviceStatus         []string `json:"device_status"`
	EnchargeCapacity     int      `json:"encharge_capacity,omitempty"`
	EnchargeRev          int      `json:"encharge_rev,omitempty"`
	ImgLoadDate          int      `json:"img_load_date"`
	ImgPnumRunning       string   `json:"img_pnum_running"`
	Installed            int      `json:"installed"`
	LastRptDate          int      `json:"last_rpt_date"`
	LedStatus            int      `json:"led_status,omitempty"`
	MainsAdminState      string   `json:"mains_admin_state,omitempty"`
	MainsOperState       string   `json:"mains_oper_state,omitempty"`
	MaxCellTemp          int      `json:"maxCellTemp,omitempty"`
	PartNum              string   `json:"part_num"`
	PercentFull          int      `json:"percentFull,omitempty"`
	Phase                string   `json:"phase,omitempty"`
	ReportedEncGridState string   `json:"reported_enc_grid_state,omitempty"`
	SerialNum            string   `json:"serial_num"`
	SleepEnabled         bool     `json:"sleep_enabled"`
	Temperature          int      `json:"temperature"`
}
