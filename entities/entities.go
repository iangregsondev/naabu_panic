package entities

type Config struct {
	LogLevel    string
	LogFilepath string
}

type TemplateVersion struct {
	ID           *int64
	MajorVersion int64
	MinorVersion int64
	PatchVersion int64
}

type ScanResult struct {
	ScanID   string
	ScanData []ScanData
	Error    error
}

type ScanData struct {
	TemplateID  string
	Name        string
	Description string
	Type        string
	Tags        []string
	Host        string
	Port        string
}

type DiscoverResult struct {
	DiscoverID string
	Results    []string
	Error      error
}

type DiscoverCommandData struct {
	ID       string
	Targets  []string
	ScanType string
	TopPorts string
}

type ScanCommandData struct {
	ID     string
	Ranges []string
	Tags   []string
}
