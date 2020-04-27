package rpc

import (
	"bytes"
	"fmt"
	"net/http"

	"gopkg.in/vmihailenco/msgpack.v2"
)

type sessionListReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type SessionListRes struct {
	ID          uint32 `msgpack:",omitempty"`
	Type        string `msgpack:"type"`
	TunnelLocal string `msgpack:"tunnel_local"`
	TunnelPeer  string `msgpack:"tunnel_peer"`
	ViaExploit  string `msgpack:"via_exploit"`
	ViaPayload  string `msgpack:"via_payload"`
	Description string `msgpack:"desc"`
	Info        string `msgpack:"info"`
	Workspace   string `msgpack:"workspace"`
	SessionHost string `msgpack:"session_host"`
	SessionPort int    `msgpack:"session_port"`
	Username    string `msgpack:"username"`
	UUID        string `msgpack:"uuid"`
	ExploitUUID string `msgpack:"exploit_uuid"`
}

type loginReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Username string
	Password string
}

type loginRes struct {
	Result       string `msgpack:"result"`
	Token        string `msgpack:"token"`
	Error        bool   `msgpack:"error"`
	ErrorClass   string `msgpack:"error_class"`
	ErrorMessage string `msgpack:"error_message"`
}

type logoutReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	LogoutToken string
}

type logoutRes struct {
	Result string `msgpack:"result"`
}

type sessionWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type sessionWriteRes struct {
	WriteCount string `msgpack:"write_count"`
}

type sessionReadReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	SessionID   uint32
	ReadPointer string
}

type sessionReadRes struct {
	Seq  uint32 `msgpack:"seq"`
	Data string `msgpack:"data"`
}

type sessionRingLastReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type sessionRingLastRes struct {
	Seq uint32 `msgpack:"seq"`
}

type Metasploit struct {
	host  string
	user  string
	pass  string
	token string
}

func New(host, user, pass string) (*Metasploit, error) {
	msf := &Metasploit{
		host: host,
		user: user,
		pass: pass,
	}

	if err := msf.Login(); err != nil {
		return nil, err
	}

	return msf, nil
}

func (msf *Metasploit) send(req interface{}, res interface{}) error {
	buf := new(bytes.Buffer)
	msgpack.NewEncoder(buf).Encode(req)
	dest := fmt.Sprintf("http://%s/api", msf.host)
	response, err := http.Post(dest, "binary/message-pack", buf)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if err := msgpack.NewDecoder(response.Body).Decode(&res); err != nil {
		return err
	}
	return nil
}

func (msf *Metasploit) Login() error {
	ctx := &loginReq{
		Method:   "auth.login",
		Username: msf.user,
		Password: msf.pass,
	}

	var res loginRes
	if err := msf.send(ctx, &res); err != nil {
		fmt.Println("Failed at login")
		return err
	}
	msf.token = res.Token
	return nil
}

func (msf *Metasploit) Logout() error {
	ctx := &logoutReq{
		Method:      "auth.logout",
		Token:       msf.token,
		LogoutToken: msf.token,
	}

	var res logoutRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}
	msf.token = ""
	return nil
}

func (msf *Metasploit) SessionList() (map[uint32]SessionListRes, error) {
	req := &sessionListReq{
		Method: "session.list",
		Token:  msf.token,
	}

	res := make(map[uint32]SessionListRes)
	if err := msf.send(req, &res); err != nil {
		return nil, err
	}

	for id, session := range res {
		session.ID = id
		res[id] = session
	}
	return res, nil

}

func (msf *Metasploit) SessionReadPointer(session uint32) (uint32, error) {
	ctx := &sessionRingLastReq{
		Method:    "session.ring_last",
		Token:     msf.token,
		SessionID: session,
	}

	var sesRingLast sessionRingLastRes
	if err := msf.send(ctx, &sesRingLast); err != nil {
		return 0, err
	}

	return sesRingLast.Seq, nil
}

func (msf *Metasploit) SessionWrite(session uint32, command string) error {
	ctx := &sessionWriteReq{
		Method:    "session.shell_write",
		Token:     msf.token,
		SessionID: session,
		Command:   command,
	}

	var res sessionWriteRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}

	return nil
}

func (msf *Metasploit) SessionRead(session uint32, readPointer uint32) (string, error) {
	ctx := &sessionReadReq{
		Method:      "session.shell_read",
		Token:       msf.token,
		SessionID:   session,
		ReadPointer: string(readPointer),
	}

	var res sessionReadRes
	if err := msf.send(ctx, &res); err != nil {
		return "", err
	}

	return res.Data, nil
}
func (msf *Metasploit) SessionExecute(session uint32, command string) (string, error) {
	readPointer, err := msf.SessionReadPointer(session)
	if err != nil {
		return "", err
	}
	msf.SessionWrite(session, command)
	data, err := msf.SessionRead(session, readPointer)
	if err != nil {
		return "", err
	}
	return data, nil
}

func (msf *Metasploit) SessionExecuteList(session uint32, commands []string) (string, error) {
	var results string
	for _, command := range commands {
		tCommand := fmt.Sprintf("%s\n", command)
		result, err := msf.SessionExecute(session, tCommand)
		if err != nil {
			return results, err
		}
		results += result
	}

	return results, nil
}
