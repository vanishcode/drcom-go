package drcom

// DrCOMDealer defines the keep-alive interface shared by U31 and U62.
type DrCOMDealer interface {
	SendAlivePkt1() error
	SendAlivePkt2() error
	Close() error
}
