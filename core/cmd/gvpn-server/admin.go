package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"

	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/server"
)

// enrollCoords are the server coordinates baked into emitted enrollment links.
type enrollCoords struct {
	Host string // host:port the client dials (GOST :443)
	SNI  string // TLS server name
	CAFp string // optional GOST cert fingerprint to pin
}

// adminServer renders the operator console and applies actions against the live
// store and server. It is mounted behind basicAuth by the serve wiring.
type adminServer struct {
	srv    *server.Server
	store  *provision.FileStore
	tokens *shareTokenStore
	coords enrollCoords
	mux    *http.ServeMux
}

func newAdminServer(srv *server.Server, store *provision.FileStore, tokens *shareTokenStore, coords enrollCoords) *adminServer {
	a := &adminServer{srv: srv, store: store, tokens: tokens, coords: coords, mux: http.NewServeMux()}
	a.mux.HandleFunc("/", a.dashboard)
	a.mux.HandleFunc("/users/add", a.addUser)
	a.mux.HandleFunc("/users/remove", a.removeUser)
	a.mux.HandleFunc("/users/enroll", a.setEnroll)
	a.mux.HandleFunc("/users/cap", a.setCap)
	a.mux.HandleFunc("/devices/revoke", a.revokeDevice)
	a.mux.HandleFunc("/share/mint", a.mintShare)
	return a
}

func (a *adminServer) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// enrollLinkFor builds the gvpn://enroll URI for a user from its enroll PSK.
func (a *adminServer) enrollLinkFor(handle string) (string, error) {
	u, ok := a.store.User(handle)
	if !ok {
		return "", fmt.Errorf("unknown user %q", handle)
	}
	uid, err := provision.ParseDeviceID(u.ID)
	if err != nil {
		return "", err
	}
	psk, ok := a.store.EnrollPSK(uid)
	if !ok {
		return "", fmt.Errorf("no enroll psk for %q", handle)
	}
	link := provision.EnrollLink{
		User: handle, EnrollPSK: psk, Host: a.coords.Host, ServerName: a.coords.SNI, CertFP: a.coords.CAFp,
	}
	return link.URI(), nil
}

type dashboardData struct {
	ActiveCount int
	Users       []provision.User
	Devices     []provision.Device
}

func (a *adminServer) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := dashboardData{
		ActiveCount: len(a.srv.ActiveDevices()),
		Users:       a.store.Users(),
		Devices:     a.store.Devices(),
	}
	render(w, dashboardTmpl, data)
}

func (a *adminServer) addUser(w http.ResponseWriter, r *http.Request) {
	handle := r.FormValue("handle")
	if handle == "" {
		http.Error(w, "handle required", http.StatusBadRequest)
		return
	}
	if _, _, err := a.store.AddUser(handle); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	uri, err := a.enrollLinkFor(handle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, enrollLinkTmpl, struct {
		Handle string
		URI    string
	}{handle, uri})
}

func (a *adminServer) removeUser(w http.ResponseWriter, r *http.Request) {
	handle := r.FormValue("handle")
	// Revoke each of the user's devices (drops live peers + conns), then remove.
	for _, d := range a.store.Devices() {
		if d.User == handle {
			if id, err := provision.ParseDeviceID(d.DeviceID); err == nil {
				_ = a.srv.RevokeDevice(id)
			}
		}
	}
	if err := a.store.RemoveUser(handle); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *adminServer) setEnroll(w http.ResponseWriter, r *http.Request) {
	handle := r.FormValue("handle")
	open := r.FormValue("open") == "true"
	if err := a.store.SetEnrollOpen(handle, open); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *adminServer) setCap(w http.ResponseWriter, r *http.Request) {
	handle := r.FormValue("handle")
	cap, err := strconv.Atoi(r.FormValue("cap"))
	if err != nil {
		http.Error(w, "cap must be an integer", http.StatusBadRequest)
		return
	}
	if err := a.store.SetDeviceCap(handle, cap); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *adminServer) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id, err := provision.ParseDeviceID(r.FormValue("device_id"))
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return
	}
	if err := a.srv.RevokeDevice(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *adminServer) mintShare(w http.ResponseWriter, r *http.Request) {
	handle := r.FormValue("handle")
	if _, ok := a.store.User(handle); !ok {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	tok, err := a.tokens.Mint(handle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, shareLinkTmpl, struct {
		Handle string
		Path   string
	}{handle, "/enroll/" + tok})
}

func render(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var dashboardTmpl = template.Must(template.New("dash").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>gvpn admin</title></head><body>
<h1>gvpn admin</h1>
<p>Active connections: {{.ActiveCount}}</p>
<h2>Add user</h2>
<form method="post" action="/users/add"><input name="handle" placeholder="handle"><button>Add user</button></form>
<h2>Users</h2>
<table border="1" cellpadding="4"><tr><th>handle</th><th>cap</th><th>enroll open</th><th>disabled</th><th>actions</th></tr>
{{range .Users}}<tr>
<td>{{.Handle}}</td><td>{{.DeviceCap}}</td><td>{{.EnrollOpen}}</td><td>{{.Disabled}}</td>
<td>
<form method="post" action="/users/cap" style="display:inline"><input type="hidden" name="handle" value="{{.Handle}}"><input name="cap" size="3" value="{{.DeviceCap}}"><button>set cap</button></form>
<form method="post" action="/users/enroll" style="display:inline"><input type="hidden" name="handle" value="{{.Handle}}"><input type="hidden" name="open" value="{{if .EnrollOpen}}false{{else}}true{{end}}"><button>{{if .EnrollOpen}}close enroll{{else}}open enroll{{end}}</button></form>
<form method="post" action="/share/mint" style="display:inline"><input type="hidden" name="handle" value="{{.Handle}}"><button>share link</button></form>
<form method="post" action="/users/remove" style="display:inline"><input type="hidden" name="handle" value="{{.Handle}}"><button>remove</button></form>
</td></tr>{{end}}</table>
<h2>Devices</h2>
<table border="1" cellpadding="4"><tr><th>device id</th><th>user</th><th>tunnel ip</th><th>source</th><th>actions</th></tr>
{{range .Devices}}<tr>
<td>{{.DeviceID}}</td><td>{{.User}}</td><td>{{.TunnelIP}}</td><td>{{.Source}}</td>
<td><form method="post" action="/devices/revoke"><input type="hidden" name="device_id" value="{{.DeviceID}}"><button>revoke</button></form></td>
</tr>{{end}}</table>
</body></html>`))

var enrollLinkTmpl = template.Must(template.New("enroll").Parse(`<!doctype html><html><body>
<h1>Created user {{.Handle}}</h1>
<p>Enrollment link (deliver securely; reusable):</p>
<pre>{{.URI}}</pre>
<p><a href="/">back</a></p>
</body></html>`))

var shareLinkTmpl = template.Must(template.New("share").Parse(`<!doctype html><html><body>
<h1>Share link for {{.Handle}}</h1>
<p>Open this on the device's phone browser (valid for a limited time):</p>
<pre>{{.Path}}</pre>
<p><a href="/">back</a></p>
</body></html>`))
