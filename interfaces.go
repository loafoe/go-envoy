package envoy

type Notification interface {
	JWTRefreshed(string)
	JWTError(error)
	SessionRefreshed(string)
	SessionUsed(string)
	SessionError(error)
}

var NilNotification = nilNotification{}

type nilNotification struct {
}

func (n nilNotification) JWTRefreshed(_ string) {

}

func (n nilNotification) JWTError(_ error) {
}

func (n nilNotification) SessionRefreshed(_ string) {

}

func (n nilNotification) SessionUsed(_ string) {

}

func (n nilNotification) SessionError(_ error) {
}
